#!/usr/bin/env python

import sys
from setuptools import setup

if sys.version_info < (3, 6):
	raise NotImplementedError("Sorry, you need at least Python 3.6+ to use jwsgi.")

import jwsgi

setup(name='jwsgi',
	version='.'.join(jwsgi.version),
	description=jwsgi.__doc__.split("\n")[0],
	long_description=jwsgi.__doc__,
	long_description_content_type="text/markdown",
	author='James Milne',
	author_email='admin@sixteenmm.org',
	url='https://git.sr.ht/~shakna/jwsgi',
	py_modules=['jwsgi'],
	scripts=['jwsgi.py'],
	license='BSD-3-Clause',
	platforms='any',
	classifiers=['Development Status :: 3 - Alpha',
				'License :: OSI Approved :: BSD License',
				'Operating System :: OS Independent',
				'Intended Audience :: Developers',
				'Topic :: Internet :: WWW/HTTP :: Dynamic Content :: CGI Tools/Libraries',
				'Topic :: Internet :: WWW/HTTP :: WSGI',
				'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
				'Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware',
				'Topic :: Software Development :: Libraries :: Application Frameworks',
				'Programming Language :: Python :: 3 :: Only',
				'Programming Language :: Python :: 3.6',
				'Programming Language :: Python :: 3.7',
				'Programming Language :: Python :: 3.8',
				'Programming Language :: Python :: 3.9',
	]
)
