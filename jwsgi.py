"""A WSGI Framework for Python

jwsgi is a WSGI framework designed to be simple, predictable, but practical.

	import jwsgi

	app = jwsgi.App()

	@app.route("/")
	@app.route("/{name:str}")
	def index(self, request, response):
		try:
			name = self['name']
		except KeyError:
			name = "World"

		return "<h1>Hello, {name}!</h1>".format(name=name)

	@app.route("/data")
	def data_route(self, request, response):
		return {
			"datum": [1, 2, 3, 4],
			"another": "Some info..."
		}

	if __name__ == "__main__":
		app.run()

See more [here](https://git.sr.ht/~shakna/jwsgi).
"""

import io
import functools
import urllib.parse
import json
import email
import http.cookies
import pathlib
import string
import types
import builtins
import itertools
import hashlib
import datetime
import shlex
import base64
import hmac

version = (0, 1, 0)

class Template(string.Formatter):
	def format(self, format_string, *args, **kwargs):
		# Expose arguments...
		self.args = args
		self.kwargs = kwargs

		return super(Template, self).format(format_string, *args, **kwargs)

	def format_field(self, value, spec):
		if spec.startswith('foreach'):
			template = spec.partition(':')[-1]
			if type(value) is dict:
				value = value.items()
			return ''.join([Template().format(template, item=item) for item in value])
		elif spec.startswith('foridx'):
			template = spec.partition(':')[-1]
			if type(value) is dict:
				value = value.items()
			return ''.join([Template().format(template, item=item, idx=idx) for idx, item in enumerate(value)])
		# TODO: <for:BIND:var:>
		elif spec == '!' or spec == '()':
			return value()
		elif spec.startswith("(") and spec.endswith(')'):
			# Grab the arguments...
			args = shlex.split(spec[1:-1])

			# Turn the arguments into their equivalents...
			built_args = []
			for arg in args:
				# Allow the user to not realise how args are broken up...
				if arg.endswith(","):
					arg = arg[:-1]

				# Use a template-aware sensible default:
				if arg in self.kwargs:
					built_args.append(self.kwargs[arg])
				else:
					built_args.append(arg)

			# Call the function:
			return value(*built_args)
		elif spec.startswith('if'):
			x = len(spec.partition(':')[-1].partition(':')[-1] or '')
			# If-only
			if x == 0:
				return (value and spec.partition(':')[-1]) or (spec.partition(':')[-1].partition(':')[-1] or '')
			else:
				# If-else
				x = x + 1
				return (value and spec.partition(':')[-1][:-x]) or (spec.partition(':')[-1].partition(':')[-1] or '')
		else:
			return super(Template, self).format_field(value, spec)

	def parse(self, format_string):
		t = super(Template, self).parse(format_string)
		t = list(t)

		for cell in t:
			literal_text, field_name, format_spec, conversion = cell
			if format_spec and format_spec.startswith('(') and format_spec.endswith(')'):
				# We don't need to rearrange anything on a function call!
				yield cell
			elif not format_spec:
				# No spec, make no changes!
				yield cell
			else:
				# Invert field/spec, slicing as appropriate...
				field_name = field_name + ":" + format_spec.partition(":")[-1]
				format_spec = format_spec.partition(":")[0].lstrip()
				yield (literal_text, format_spec, field_name, conversion)

def environ_defaults(environ):
	# The HTTP request method, such as "GET" or "POST".
	# This cannot ever be an empty string, and so is always required.
	try:
		if not environ['REQUEST_METHOD']:
			environ['REQUEST_METHOD'] = 'GET'
	except KeyError:
		environ['REQUEST_METHOD'] = 'GET'

	# The initial portion of the request URL's "path" that corresponds
	# to the application object,
	# so that the application knows its virtual "location".
	# This _may_ be an empty string, if the application corresponds
	# to the "root" of the server.
	try:
		environ['SCRIPT_NAME']
	except KeyError:
		environ['SCRIPT_NAME'] = ''

	# The remainder of the request URL's "path", [after SCRIPT_NAME],
	# designating the virtual "location" of the request's target within the application.
	# This may be an empty string, if the request URL targets the application root
	# and does not have a trailing slash.
	try:
		environ['PATH_INFO']
	except KeyError:
		environ['PATH_INFO'] = ''

	# The portion of the request URL that follows the "?", if any.
	# May be empty or absent.
	try:
		environ['QUERY_STRING']
	except KeyError:
		environ['QUERY_STRING'] = ''

	# The contents of any Content-Type fields in the HTTP request.
	# May be empty or absent.
	try:
		if not environ['CONTENT_TYPE']:
			# Empty string, fallback to default behaviour.
			raise KeyError
	except KeyError:
		environ['CONTENT_TYPE'] = ''

	# Doesn't exist in WSGI spec. We use it, however.
	try:
		if not environ['CONTENT_ENCODING']:
			# Empty sting, fallback to default behaviour.
			raise KeyError
	except KeyError:
		environ['CONTENT_ENCODING'] = 'utf-8'

	# The contents of any Content-Length fields in the HTTP request.
	# May be empty or absent.
	try:
		environ['CONTENT_LENGTH'] = int(environ['CONTENT_LENGTH'] or 0)
	except ValueError:
		# Fallback to default...
		raise KeyError
	except KeyError:
		# This can't be calculated. The only safe answer is this.
		environ['CONTENT_LENGTH'] = 0

	# When HTTP_HOST is not set, these variables can be combined to determine a default.
	# SERVER_NAME and SERVER_PORT are required strings and must never be empty.
	try:
		environ['SERVER_NAME']
		environ['SERVER_PORT']
	except KeyError:
		try:
			environ['SERVER_NAME'] = environ['HTTP_HOST'].split(":")[0]
			environ['SERVER_PORT'] = environ['HTTP_HOST'].split(":")[1]
		except IndexError:
			# Badly behaved HTTP_HOST
			raise KeyError
		except KeyError:
			# Default values
			environ['SERVER_NAME'] = 'localhost'
			environ['SERVER_PORT'] = 8080

	# The version of the protocol the client used to send the request.
	# Typically this will be something like "HTTP/1.0" or "HTTP/1.1"
	# and may be used by the application to determine how to treat any HTTP request headers.
	# (This variable should probably be called REQUEST_PROTOCOL, since it denotes the protocol
	# used in the request, and is not necessarily the protocol that will be used in the server's response.
	# However, for compatibility with CGI we have to keep the existing name.)
	try:
		environ['SERVER_PROTOCOL']
	except KeyError:
		# Sensible default...
		environ['SERVER_PROTOCOL'] = 'HTTP/1.1'

	# Note: HTTP_* names:
	# Variables corresponding to the client-supplied HTTP request headers
	# (i.e., variables whose names begin with "HTTP_").
	# The presence or absence of these variables should correspond with the
	# presence or absence of the appropriate HTTP header in the request.

	# The tuple (1, 0), representing WSGI version 1.0.
	environ['wsgi.version'] = (1, 0)

	# A string representing the "scheme" portion of the URL at
	# which the application is being invoked.
	# Normally, this will have the value "http" or "https", as appropriate.
	try:
		environ['wsgi.url_scheme']
	except KeyError:
		environ['wsgi.url_scheme'] = environ['SERVER_PROTOCOL'].split("/")[0].lower()

	# An input stream (file-like object) from which the HTTP request
	# body bytes can be read. (The server or gateway may perform reads
	# on-demand as requested by the application, or it may pre- read
	# the client's request body and buffer it in-memory or on disk,
	# or use any other technique for providing such an input stream,
	# according to its preference.)
	try:
		environ['wsgi.input']
	except KeyError:
		environ['wsgi.input'] = io.BytesIO()

	# An output stream (file-like object) to which error output can be written,
	# for the purpose of recording program or other errors in a standardized
	# and possibly centralized location. This should be a "text mode"
	# stream; i.e., applications should use "\n" as a line ending, and assume
	# that it will be converted to the correct line ending by the server/gateway.

	# (On platforms where the str type is unicode, the error stream should
	# accept and log arbitrary unicode without raising an error; it is allowed,
	# however, to substitute characters that cannot be rendered in the stream's encoding.)

	# For many servers, wsgi.errors will be the server's main error log.
	# Alternatively, this may be sys.stderr, or a log file of some sort.
	# The server's documentation should include an explanation of how to configure
	# this or where to find the recorded output.
	# A server or gateway may supply different error streams to different applications, if this is desired.
	try:
		environ['wsgi.errors']
	except KeyError:
		environ['wsgi.errors'] = io.StringIO()

	# This value should evaluate true if the application object may be simultaneously
	# invoked by another thread in the same process, and should evaluate false otherwise.
	try:
		environ['wsgi.multithread']
	except KeyError:
		environ['wsgi.multithread'] = False

	# This value should evaluate true if an equivalent application object may be simultaneously
	# invoked by another process, and should evaluate false otherwise.
	try:
		environ['wsgi.multiprocess']
	except KeyError:
		environ['wsgi.multiprocess'] = False

	# This value should evaluate true if the server or gateway expects
	# (but does not guarantee!) that the application will only be invoked
	# this one time during the life of its containing process. Normally,
	# this will only be true for a gateway based on CGI (or something similar).
	try:
		environ['wsgi.run_once']
	except KeyError:
		environ['wsgi.run_once'] = False

	# Our own server values...
	environ['jwsgi.version'] = version
	environ['SERVER_SOFTWARE'] = 'jwsgi:{}'.format('.'.join(environ['jwsgi.version']))
	environ['jwsgi.template_directory'] = 'templates'

	return environ

def status_code(code):
	# https://www.iana.org/assignments/http-status-codes/http-status-codes.txt

	informational = {
		100: "Continue",
		101: "Switching Protocols",
		102: "Processing",
		103: "Early Hints"
	}
	for i in range(104, 200):
		informational[i] = "Unassigned"

	success = {
		200: "OK",
		201: "Created",
		202: "Accepted",
		203: "Non-Authoritative Information",
		204: "No Content",
		205: "Reset Content",
		206: "Partial Content",
		207: "Multi-Status",
		208: "Already Reported"
	}
	for i in range(209, 226):
		success[i] = "Unassigned"
	
	success[226] = "IM Used"
	
	for i in range(227, 300):
		success[i] = "Unassigned"

	redirection = {
		300: "Multiple Choices",
		301: "Moved Permanently",
		302: "Found",
		303: "See Other",
		304: "Not Modified",
		305: "Use Proxy",
		306: "(Unused)",
		307: "Temporary Redirect",
		308: "Permanent Redirect"
	}
	for i in range(309, 400):
		redirection[i] = "Unassigned"

	client_error = {
		400: "Bad Request",
		401: "Unauthorized",
		402: "Payment Required",
		403: "Forbidden",
		404: "Not Found",
		405: "Method Not Allowed",
		406: "Not Acceptable",
		407: "Proxy Authentication Required",
		408: "Request Timeout",
		409: "Conflict",
		410: "Gone",
		411: "Length Required",
		412: "Precondition Failed",
		413: "Payload Too Large",
		414: "URI Too Long",
		415: "Unsupported Media Type",
		416: "Range Not Satisfiable",
		417: "Expectation Failed",
		421: "Misdirected Request",
		422: "Unprocessable Entity",
		423: "Locked",
		424: "Failed Dependency",
		425: "Too Early",
		426: "Upgrade Required",
		428: "Precondition Required",
		429: "Too Many Requests",
		431: "Request Header Fields Too Large",
		451: "Unavailable For Legal Reasons"
	}
	for i in range(418, 421):
		client_error[i] = "Unassigned"
	client_error[427] = "Unassigned",
	client_error[430] = "Unassigned"
	for i in range(432, 451):
		client_error[i] = "Unassigned"

	server_error = {
		500: "Internal Server Error",
		501: "Not Implemented",
		502: "Bad Gateway",
		503: "Service Unavailable",
		504: "Gateway Timeout",
		505: "HTTP Version Not Supported",
		506: "Variant Also Negotiates",
		507: "Insufficient Storage",
		508: "Loop Detected",
		510: "Not Extended",
		511: "Network Authentication Required"
	}
	server_error[509] = "Unassigned"
	for i in range(512, 600):
		server_error[i] = "Unassigned"

	code_dict = {}
	code_dict = {**code_dict, **informational}
	code_dict = {**code_dict, **success}
	code_dict = {**code_dict, **redirection}
	code_dict = {**code_dict, **client_error}
	code_dict = {**code_dict, **server_error}

	try:
		return code_dict[code]
	except KeyError:
		return 'Unknown'

class DictNamespace(object):
	def __init__(self, **kwargs):
		self.datum = types.SimpleNamespace(**kwargs)

	def __getattr__(self, name):
		try:
			return getattr(self.datum, name)
		except TypeError:
			return self.__getitem__(name)

	def __repr__(self):
		return self.datum.__repr__()

	def __eq__(self, other):
		if isinstance(self, DictNamespace) and isinstance(other, DictNamespace):
			return self.datum == other.datum
		else:
			return False

	def __getitem__(self, item):
		try:
			return getattr(self.datum, item)
		except AttributeError:
			raise KeyError

class Request(object):
	def __init__(self, environ, secret=None, digestmod=hashlib.sha512):
		self.environ = environ_defaults(environ)
		self.secret = secret
		self.digestmod = digestmod

	def __str__(self):
		return "Request({})".format(str(self.environ))

	def data(self):
		"""
		Combined access to json, form, and query data.
		"""

		d = []
		if self.environ['CONTENT_TYPE'] == 'application/json':
			d.extend(list(self.json().items()))
		else:
			d.extend(self.form())
		d.extend(self.query())

		return d

	def cookies(self):
		try:
			jar = http.cookies.BaseCookie(self.environ['HTTP_COOKIE'])

			# Convert to dictionary for easier life...
			ret = {}
			for k, v in jar.items():
				ret[k] = dict(v)
				ret[k]['value'] = v.value

				# Workaround for if Python decides to add quoting...
				if v.value[0] == '"' and v.value[-1] == '"':
					ret[k]['value'] = v.value[1:-1]

				# Detect if secret, and try and decode...
				if self.secret != None:
					try:
						# Probably one of our secret cookies...
						if ret[k]['value'][0] == '!':
							# Extract out our signature and data...
							sig, _, datum = ret[k]['value'].partition('?')
							sig = sig[1:]

							# Prepare for comparison
							sig = base64.b64decode(sig)
							datum = datum.encode()

							# Pull down the secret so we aren't modifying it in place
							secret = self.secret
							if isinstance(secret, str):
								secret = secret.encode()
							
							# Construct a comparison signature
							try:
								sig2 = hmac.new(secret, datum, digestmod=self.digestmod).digest()

								# Run a comparison...
								if hmac.compare_digest(sig, sig2):
									datum = base64.b64decode(datum).decode()
									
									# If its json, decode it...
									try:
										datum = json.loads(datum)
									except:
										pass

									# Worked, return decoded data!
									ret[k]['value'] = datum
							except:
								pass

					except IndexError:
						pass

			return ret
		except http.cookies.CookieError:
			return {}
		except KeyError:
			return {}

	def get_cookie(self, name, default=None):
		cookies = self.cookies()
		if not cookies:
			return default

		try:
			return cookies[name]
		except KeyError:
			return default

	def query(self):
		return urllib.parse.parse_qs(self.environ['QUERY_STRING'])

	def body(self):
		# Prevent reading problems...
		if hasattr(self, '_input'):
			return self._input

		# TODO: Limits...

		# TODO: Reflect encoding...

		self._input = self.environ['wsgi.input'].read(int(self.environ['CONTENT_LENGTH']))
		return self._input

	def json(self):
		if self.environ['CONTENT_TYPE'] == 'application/json':
			raw = self.body()
			try:
				return json.loads(raw)
			except:
				return {}
		else:
			return {}

	def form(self):
		if self.environ['CONTENT_TYPE'] == 'application/x-www-form-urlencoded':
			raw = self.body()
			return urllib.parse.parse_qsl(raw)
		elif self.environ['CONTENT_TYPE'].startswith('multipart/form-data;'):
			raw = self.body()
			
			# Fake it being an email...
			msg = (b"MIME-Version: 1.0\r\nContent-Type:"
				+ self.environ['CONTENT_TYPE'].replace("multipart/form-data;", "multipart/mixed;").encode()
				+ b"\r\n\r\n"
				+ raw)

			msg = email.message_from_string(msg.decode())
			if msg.is_multipart():
				data = []
				for part in msg.get_payload():
					name = part.get_param('name', header='content-disposition')
					filename = part.get_param('filename', header='content-disposition')
					payload = part.get_payload(decode=True)
					data.append({"name": name, "filename": filename, "content": payload})
				return data

		return []

	def uri(self):
		url = self.environ['wsgi.url_scheme']+'://'
		try:
			url += self.environ['HTTP_HOST']
		except KeyError:
			url += self.environ['SERVER_NAME']
			url += ':' + self.environ['SERVER_PORT']
		url += urllib.parse.quote(self.environ['SCRIPT_NAME'])
		url += urllib.parse.quote(self.environ['PATH_INFO'])

		if self.environ['QUERY_STRING']:
			url += '?' + self.environ['QUERY_STRING']

		return urllib.parse.urlparse(url)

class Response(object):
	def __init__(self, environ, secret=None, digestmod=hashlib.sha512):
		self.environ = environ_defaults(environ)
		self._cookies = False
		self.secret = secret
		self.digestmod = digestmod

	def headers(self):
		headers = []

		# Things that shouldn't be handed back...
		not_headers = ['HTTP_USER_AGENT',
		'HTTP_HOST',
		'HTTP_STATUS',
		'HTTP_PROXY_ATHENTICATE',
		'HTTP_PROXY_AUTHORIZATION',
		'HTTP_TRANSFER_ENCODING',
		'HTTP_UPGRADE']

		# Ban when Hop-By-Hop
		try:
			if self.environ['HTTP_CONNECTION'].lower() == 'keep-alive':
				not_headers.append('HTTP_CONNECTION')
		except KeyError:
			pass
		try:
			if self.environ['HTTP_TE'].lower() == 'trailers':
				not_headers.append('HTTP_TE')
		except KeyError:
			pass

		# Other headers...
		for key, value in self.environ.items():
			if key.startswith("HTTP_") and key not in not_headers:
				# Handle Multi-headers:
				if isinstance(value, list):
					for v in value:
						headers.append((key[5:], v))
				else:
					headers.append((key[5:], str(value)))

		# Set-Cookie headers...
		if self._cookies:
			for cookie in self._cookies.values():
				headers.append(('Set-Cookie', cookie.output(header='').lstrip()))

		# Set the Content Type
		headers.append(("Content-Type", "{}; charset={}".format(self.environ['CONTENT_TYPE'], self.environ['CONTENT_ENCODING'])))

		return headers

	def get_header(self, key, default=None):
		return self.environ.get('HTTP_{}'.format(key), default)

	def set_header(self, key, value):
		self.environ['HTTP_{}'.format(key)] = value

	def append_header(self, key, value):
		try:
			if isinstance(self.environ['HTTP_{}'.format(key)], str):
				self.environ['HTTP_{}'.format(key)] = [self.environ['HTTP_{}'.format(key)]]
			self.environ['HTTP_{}'.format(key)].append(value)
		except KeyError:
			self.environ['HTTP_{}'.format(key)] = [value]

	def set_cookie(self, name, value, **options):
		secret = self.secret
		digestmod = self.digestmod

		if not self._cookies:
			self._cookies = http.cookies.SimpleCookie()

		# Enable this...
		if 'secure' in options:
			if secret == None:
				raise http.cookies.CookieError('Secure requires secret.')

			options['httponly'] = True

			# The key should have a default lifetime...
			if 'maxage' not in options:
				options['maxage'] = 24 * 3600

			if isinstance(secret, str):
				secret = secret.encode()

			if isinstance(value, dict) or isinstance(value, list):
				value = json.dumps(value)
			value = value.encode()

			enc = base64.b64encode(value)
			sig = base64.b64encode(hmac.new(secret, enc, digestmod=digestmod).digest())
			value = "!{sig}?{enc}".format(enc=enc.decode(), sig=sig.decode())

		# Cookies have a 4kb limit. And what 4Kb is can slightly differ across browsers...
		if len(name) + len(value) > 3800:
			raise ValueError('Exceeds maximum allowed cookie length.')

		# Set the man cookie value...
		self._cookies[name] = value

		# Set the attributes
		for key, value in options.items():
			if key.lower() in ('max_age', 'maxage', 'max-age'):
				key = 'max-age'
				if isinstance(value, datetime.timedelta):
					value = value.seconds + value.days * 24 * 3600
			if key == 'expires':
				# Handle basic datetime conversions:
				if isinstance(value, datetime.datetime):
					value = value.utctimetuple()
				elif isinstance(value, datetime.date):
					value = value.timetuple()
				if not isinstance(value, (int, float)):
					value = calendar.timegm(value)
				value = email.utils.formatdate(value, usegmt=True)
			if key in ('same_site', 'samesite', 'same-site'):
				key = 'samesite'
				value = (value or "none").lower()
				if value not in ('lax', 'strict', 'none'):
					raise http.cookies.CookieError("Invalid samesite: {}".format(value))
			if key in ('secure', 'httponly') and not value:
				# Ignore disabling something we haven't set...
				continue
			# Set the attribute
			self._cookies[name][key] = value

	def del_cookie(self, key, **kwargs):
		"""
		Delete a cookie.
		Footgun: path and domain must be the same as original cookie.
		"""
		self.set_cookie(key, '', max_age=-1, expires=0, **kwargs)

	def redirect(self, path):
		"""
		Generate a 303 return to the given path.
		The result should be returned by the routing function.
		"""
		self.environ['HTTP_STATUS'] = 303
		self.set_header("Refresh", "0; URL={}".format(path))
		return b''

	def set_content_type(self, content_type):
		self.environ['CONTENT_TYPE'] = content_type

	def set_content_encoding(self, content_encoding):
		self.environ['CONTENT_ENCODING'] = content_encoding

	def render_template(self, filename, **kwargs):
		"""
		A truly horrible template system...
		"""
		root = pathlib.Path(self.environ['jwsgi.template_directory'])

		if '_FILE_' not in kwargs:
			kwargs['_FILE_'] = filename

		# Allow including other templates inside itself:
		if 'include' not in kwargs:
			def inner_include(fname, **kwargs2):
				"""include(filename)"""

				# TODO: Allow args to be name/value tuples to workaround no keyword parsing in shlex?
				# Do we need to do that? It inherits the environment...

				# Combine with including context...
				inner_dict = {**kwargs, **kwargs2}

				if '_FILE_' in inner_dict:
					inner_dict['_PARENT_FILE_'] = inner_dict['_FILE_']
					inner_dict['_FILE_'] = fname

				p = root / pathlib.Path(fname)
				if p.exists():
					with open(p, 'r') as openFile:
						return Template().format(openFile.read(), **inner_dict)

			inner_include.__name__ == 'include'
			kwargs['include'] = inner_include

		p = root / pathlib.Path(filename)
		if p.exists():
			with open(p, 'r') as openFile:
				return Template().format(openFile.read(), **kwargs)

	def __str__(self):
		return "Response({})".format(str(self.environ))

class App(object):
	def __init__(self, secret=None, digestmod=hashlib.sha512):
		self.routes = {}
		self.error_routes = {}
		self.type_constructors = {}
		self._hook_before = []
		self._hook_after = []
		self.secret = secret
		self.digestmod = digestmod

		# TODO: Allow overriding response.environ['jwsgi.template_directory']...

	def add_type_constructor(self, name, fn):
		self.type_constructors[name] = fn

	def hook_before(self):
		"""
		Add a function to a list to be called before a route.
		The hook's self may be None.
		"""
		def hook_inner(func):
			@functools.wraps(func)
			def hook_wrapper(func_self, request, response):
				# Note: func_self may be None
				return func(func_self, request, response)

			self._hook_before.append(hook_wrapper)
			return hook_wrapper
		return hook_inner

	def hook_after(self):
		"""
		Add a function to a list to be called after a route.
		The hook's self may be None.
		This also runs after any error hook that may be called.
		"""
		def hook_inner(func):
			@functools.wraps(func)
			def hook_wrapper(func_self, request, response):
				# Note: func_self may be None
				return func(func_self, request, response)

			self._hook_after.append(hook_wrapper)
			return hook_wrapper
		return hook_inner

	def error(self, status_code):
		"""
		Change the response of any given HTTP status code.
		"""
		def error_route_inner(func):
			@functools.wraps(func)
			def wrapper(func_self, request, response):
				# Note: func_self may be None
				return func(func_self, request, response)

			self.error_routes[status_code] = {"fn": wrapper}

			return wrapper

		return error_route_inner

	def route(self, path_string, methods=['GET', 'HEAD', 'OPTIONS']):
		"""
		Install a function to be called for a given path,
		with an acceptable list of methods
		"""
		methods = [x.upper() for x in set(methods)]

		def route_inner(func):
			@functools.wraps(func)
			def wrapper(func_self, request, response):
				return func(func_self, request, response)

			if 'GET' in methods:
				if 'HEAD' not in methods:
					methods.append('HEAD')
				if 'OPTIONS' not in methods:
					methods.append('OPTIONS')

			self.routes[path_string] = {"fn": wrapper, "methods": methods}

			return wrapper

		return route_inner

	def get_paths(self, functor, methods=['GET']):
		"""
		Given a function or str(function name),
		find the matching route/s with the given methods
		"""

		methods = [x.upper() for x in set(methods)]
		if 'GET' in methods:
			if 'HEAD' not in methods:
				methods.append('HEAD')
			if 'OPTIONS' not in methods:
				methods.append('OPTIONS')

		try:
			search = functor.__name__
		except AttributeError:
			search = functor

		r = []
		for k, v in self.routes.items():
			if any(method in v['methods'] for method in methods):
				if v['fn'].__name__ == search:
					r.append(k)
		return r

	def run(self, host='localhost', port=8080, server=None, app=None):
		"""
		Start up a development server.
		"""

		if app == None:
			app = self.wsgi()

		if server == None:
			from wsgiref.simple_server import make_server
			with make_server(host, port, app) as httpd:
				print("WARNING: Using wsgiref's shitty server!")
				print("Running at http://{}:{}".format(host, port))
				httpd.serve_forever()
		else:
			# TODO: Basic support for handful of populars...
			raise NotImplementedError

	# Route matcher...
	def find_route(self, request):
		uri = request.uri()

		for obj, cell in self.routes.items():
			if (obj.count("{") == 0 or obj.count("}") == 0) or (obj.count("{") != obj.count("}")):
				# Treat as static route...
				if obj == uri.path:

					# Check method here...
					if request.environ.get('REQUEST_METHOD', 'GET') in cell['methods']:
						RouteObject = DictNamespace(**cell)
						return RouteObject
			else:
				# Treat as dynamic route...

				if uri.path.count("/") == obj.count("/"):
					parts_current = pathlib.PurePath(uri.path).parts
					parts_func = pathlib.PurePath(obj).parts

					if len(parts_current) == len(parts_func):
						args = {}

						found = True
						for i in range(0, len(parts_func)):
							if ((parts_func[i].count("{") == 0 or parts_func[i].count("}") == 0)
								or (parts_func[i].count("{") != parts_func[i].count("}"))):
								# Static part
								if parts_func[i] != parts_current[i]:
									found = False
									break
							else:
								# Dynamic part (interpolate data...)
								field, format_spec = [(fname, format_spec) for _, fname, format_spec, _ in string.Formatter().parse(parts_func[i]) if fname][0]

								# Support typing on dynamic parts:
								if format_spec:
									type_class = None
									# Allow custom constructors
									if format_spec in self.type_constructors:
										type_class = self.type_constructors[format_spec]
									if type_class == None:
										type_class = getattr(builtins, format_spec, None)
									if type_class == None:
										type_class = getattr(types, format_spec, None)
									
									if type_class == None:
										raise TypeError("Type converter <{}> not found.".format(format_spec))

									try:
										args[field] = type_class(parts_current[i])
									except:
										raise TypeError("Bad type <{}> for <{}>".format(type_class, parts_current[i]))
								else:
									args[field] = parts_current[i]

						if not found:
							continue
						else:
							# Check method here...
							if request.environ.get('REQUEST_METHOD', 'GET') in cell['methods']:
								r = cell.copy()
								r = {**r, **args.copy()}
								RouteObject = DictNamespace(**r)
								return RouteObject

	def wsgi(self):
		def app(environ, start_response):
			environ = environ_defaults(environ)

			# Default status code...
			code = 200

			# Build some kind of request object here...
			request = Request(environ.copy(), secret=self.secret, digestmod=self.digestmod)

			# Build some kind of response object here...
			res_env = environ.copy()
			res_env['CONTENT_TYPE'] = ''
			response = Response(res_env, secret=self.secret, digestmod=self.digestmod)

			# Call route here...
			route = None
			body = None
			try:
				route = self.find_route(request)

				if route == None:
					response.environ['HTTP_STATUS'] = 404
					
					# Run before hooks...
					for item in self._hook_before:
						item(route, request, response)

				else:

					# Run before hooks...
					for item in self._hook_before:
						item(route, request, response)

					# Run main route...
					body = route.fn(route, request, response)
			except Exception as e:
				# TODO: Debug mode...
				#print("Exception", e)
				#import traceback
				#import sys
				#traceback.print_stack()
				#print(sys.exc_info())
				# Should it go to environ['wsgi.errors']?

				if isinstance(e, TypeError):
					# User violated type specifier on route...
					response.environ['HTTP_STATUS'] = 406

					# Run before hooks...
					for item in self._hook_before:
						item(route, request, response)

				else:
					response.environ['HTTP_STATUS'] = 500

					# Run before hooks...
					for item in self._hook_before:
						item(route, request, response)

			# Get our response status
			try:
				code = int(response.environ['HTTP_STATUS'])
			except KeyError:
				code = 200
				response.environ['HTTP_STATUS'] = code
			except ValueError:
				code = 500
				response.environ['HTTP_STATUS'] = code

			# Check for errors...
			if response.environ['HTTP_STATUS'] in self.error_routes:
				body = self.error_routes[response.environ['HTTP_STATUS']]['fn'](route, request, response)
			else:
				if body == None:
					# Default error...
					body = "Error: {}".format(status_code(response.environ['HTTP_STATUS'])).encode(response.environ['CONTENT_ENCODING'])

			# Expose body for after hooks...
			response.body = body

			# Run after hooks...
			for item in self._hook_after:
				item(route, request, response)
				# Get the body from the hook...
				body = response.body
			
			body = response.body

			# Generate the status
			status = '{} {}'.format(code, status_code(code))

			# Construct the appropriate body here...
			if isinstance(body, bytes):
				if not response.environ['CONTENT_TYPE']:
					response.set_content_type("text/plain")
				ret = body
			elif isinstance(body, str):
				if not response.environ['CONTENT_TYPE']:
					response.set_content_type("text/html")
				ret = body.encode(response.environ['CONTENT_ENCODING'])
			elif isinstance(body, dict):
				# Set the output to the correct content type...
				if not response.environ['CONTENT_TYPE']:
					response.set_content_type("application/json")
				datum = json.dumps(body)
				ret = datum.encode(response.environ['CONTENT_ENCODING'])
			elif isinstance(body, list):
				# Set the output to the correct content type...
				if not response.environ['CONTENT_TYPE']:
					response.set_content_type("application/json")
				datum = json.dumps(body)
				ret = datum.encode(response.environ['CONTENT_ENCODING'])
			else:
				# Unknown! Guess how to output it...
				if not response.environ['CONTENT_TYPE']:
					response.set_content_type("application/octet-stream")
				ret = str(body).encode(response.environ['CONTENT_ENCODING'])

			# Start the response
			start_response(status, response.headers())

			# Deliver the body
			# Chunk body into 1024 byte size pieces...
			return (ret[0+i:1024+i] for i in range(0, len(ret), 1024))

		# Validate the app before returning it...
		import wsgiref.validate
		wsgiref.validate.validator(app)

		return app
