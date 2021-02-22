import jwsgi

app = jwsgi.App()

@app.route("/other/thing/")
def other(self, request, response):
	return {}

def new_constructor(value):
	return int(value)
app.add_type_constructor("constructor", new_constructor)

@app.route("/{thing:constructor}/{value}/{multiword verse}")
def thing_verse(self, request, response):
	#print(self.thing)
	#print(self['multiword verse'])

	request.environ['thing'] = "Modified!"

	#response.environ['HTTP_STATUS'] = 202

	return self

@app.route("/")
def index(self, request, response):
	#print(self['methods'])
	#print(request, response)

	#print(request.query())
	#print(request.json())
	#print(request.form())
	#print(request.data())

	#for k, v in request.cookies().items():
	#	print(k, v)

	#print(request.get_cookie("token"))

	print(self['methods'])

	print(request.environ['REQUEST_METHOD'])

	#print(self['callback'])

	#print(request.environ)

	#print("PATH", app.get_paths(serve_js))

	response.append_header("X-Multi", "A")
	response.append_header("X-Multi", "B")
	response.append_header("X-Multi", "C")

	response.set_cookie("somecookie", "simple")
	response.set_cookie("somecookie2", "secure", secure=True, httponly=True)
	response.del_cookie("somecookie")

	return response.redirect(app.get_paths(serve_js)[0].format(filename='home'))

@app.route("/static/{filename}.js")
@app.route("/{filename}.js")
def serve_js(self, request, response):
	return {"js": "thing"}

@app.hook_before()
def before(self, request, response):
	print("BEFORE!")

@app.hook_after()
def after(self, request, response):
	print("AFTER!")
	#print(response)

@app.error(404)
def error404(self, request, response):
	return 'Shoot...'

app.run()
