## Copyright 2012 Joey
## 
## httpyd is released under GPL. Please read the license before continuing.
## 
## The latest source can be found here:
##	 https://github.com/jvq2/httpyd
##
from http.server import *
import http.cookies
import traceback
import threading
import re
import urllib.parse
import os
import mimetypes
from datetime import datetime
import time
import binascii
import hashlib
import random
from configparser import ConfigParser


httpd = None
server = None
conf = None



sessions = {}


WSESSID = ''
DOC_ROOT = ''
	
	
def esc(text):
	return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')

def compURL(base, params):
	if not params: return base
	
	p = []
	for k in params:
		p += [k +'='+ urllib.parse.quote_plus(str(params[k]))]
		
	return base +'?'+ '&'.join(p)
	
	
def size_fmt(num, prec=1):
    for x in [' bytes','kb','mb','gb','tb']:
        if num < 1024.0:
            return ("%3."+str(prec)+"f%s") % (num, x)
        num /= 1024.0

	
	
class serverThread(threading.Thread):
		
		def run(self):
			global httpd
			httpd = HTTPServer((conf.get('httpd','address'), conf.getint('httpd','port')), MyHandler)
			httpd.serve_forever()

	
	
def loadConf():
	global conf, WSESSID, DOC_ROOT, DIR_INDX, RUN_PY
	
	## load configuration
	conf = ConfigParser()
	conf.read('httpd.conf')
	
	if conf.has_option('httpd', 'WSESSID'):
		WSESSID = conf.get('httpd', 'WSESSID', 'WSESSID')
	else:
		WSESSID = 'WSESSID'
		
	if conf.has_option('httpd', 'document_root'):
		DOC_ROOT = conf.get('httpd', 'document_root')
	else:
		DOC_ROOT = './htdocs/'
		
	if conf.has_option('httpd', 'dir_index'):
		DIR_INDX = conf.get('httpd', 'dir_index').split()
	else:
		DIR_INDX = []
		
	if conf.has_option('httpd', 'run_py'):
		RUN_PY = conf.getboolean('httpd', 'run_py')
	else:
		RUN_PY = False
	
	return
	
	
	
def init():
	global httpd, server
	
	loadConf()
	
	## start the server in its own thread
	server = serverThread()
	server.start()
	
def restart():
	shutdown()
	init()
	return
	
	
def shutdown():
	global MyHandler, httpd, server
	
	httpd.shutdown()
	server.join()
	

class MyHandler(BaseHTTPRequestHandler):
	server_version = 'httpyd - yup, its a server'
	querystr = ''
	post = {}
	get = {}
	set_cookies = http.cookies.SimpleCookie()
	cookies = http.cookies.SimpleCookie()
	session = {}
	sessid = ''
	
	
	
	
	##
	## Give me a fancy server version! Tell no one of server software
	##
	def version_string(s):
		return s.server_version
	
	
	
	## 
	## Gimme an Error!
	##
	def e(s, errno, short="", msg=""):
		s.send_response(int(errno))
		s.send_header("Content-type", "text/html;charset=utf-8")
		s.end_headers()
		
		s.send("<html><head><title>Error %d</title></head>" % (errno,))
		s.send("<body><h1>%d %s</h1>"%(errno,esc(short)))
		if msg:
			s.send("<p>%s</p>" % (esc(msg)))
		s.send("<p>Request path: %s</p>" % s.path)
		s.send("</body></html>")
		return
	
	
	
	## 
	## Error page: 404
	##
	def e404(s, msg=""):
		return s.e(404, "Page Not Found", msg)
	
	
	
	## 
	## Error page: 500
	##
	def e500(s, msg=""):
		return s.e(500, "Bork", msg)
	
	
	
	
	
	##
	## redirect a page BEFORE any headers are sent
	##
	def redirect(s, loc, msg="Redirecting."):
		s.send_response(302)
		s.send_header('Content-type', 'text/html;charset=utf-8')
		s.send_header('Location', loc)
		s.end_headers()
		s.send(msg)
		return
	
	
	
	
	##
	## woo code comments...
	##
	def hasHeader(s, header):
		return header in s.headers
	
	
	
	##
	## load cookies from the current request header 
	##
	def loadCookies(s):
		if 'Cookie' in s.headers:
			s.cookies.load(s.headers['Cookie'])
		return
	
	
	
	##
	## overwrite current to send cookies before headers close
	##  - sending cookies prematurely will UPSET THE NATURAL ORDER!!
	##
	def end_headers(s):
		for c in s.set_cookies:
			s.send_header('Set-Cookie', s.set_cookies[c].OutputString())
		return BaseHTTPRequestHandler.end_headers(s)
	
	
	
	##
	## Load session variables into the current scope
	##
	def session_start(s):
		global sessions, WSESSID
		
		if s.sessid: return
		
		if WSESSID in s.cookies and \
			s.cookies[WSESSID].value in sessions and \
			sessions[s.cookies[WSESSID].value]['ip'] == s.client_address[0]:
			
			s.sessid = s.cookies[WSESSID].value
		else:
			s.sessid = s.createSession()
			
			s.set_cookies[WSESSID] = s.sessid
		
		## ATTENTION:: s.session is a reference to sessions[s.sessid]['data']
		##             and it will remain that way so that data can be changed
		##             as long as s.session is not overwritten.
		##             Do not: `s.session = {'spam':'eggs'}`
		##             Do: `s.session['spam'] = 'eggs'`
		##             Do not overwrite s.session!
		##             Do modify s.session
		s.session = sessions[s.sessid]['data']
		return
	
	
	
	##
	## create a new unique session id and 
	##
	def createSession(s):
		global sessions, WSESSID
		
		m = hashlib.md5()
		
		m.update(bytes(str(s.client_address)+"_+SD65"+str(s.headers)+str(random.random()),'utf8'))
		h = m.hexdigest()
		
		while h in sessions:
			m.update(bytes(str(random.random()),'utf8'))
			h = m.hexdigest()
			
		sessions[h] = {
			'ip':			s.client_address[0],
			'useragent':	'User-Agent' in s.headers and s.headers['User-Agent'] or '',
			'data':			{'asdf':1}
			}
		return h
	
	
	##
	## shortcut for text output
	##
	def send(s, text):
		return s.wfile.write(bytes(text,'utf8'))
	
	
	##
	## HEAD request - for fetching just the header and no content
	##
	def do_HEAD(s):
		s.send_response(200)
		s.send_header("Content-type", "text/html;charset=utf-8")
		s.end_headers()
		return
	
	
	
	## 
	## GET request
	##
	def do_GET(s):
		return s.magic()
	
	
	
	## 
	## POST request
	##
	def do_POST(s):
		return s.magic()
	
	
	
	##
	## parse gets, posts then dispatch
	##
	def magic(s):
		## apparently, the server saves the instances and reuses them
		s.querystr = ''
		s.post = {}
		s.get = {}
		s.set_cookies = http.cookies.SimpleCookie()
		s.cookies = http.cookies.SimpleCookie()
		s.session = {}
		s.sessid = ''
		
		## COOKIE MONSTER!! OMNOMNOMONOMNOM
		s.loadCookies()
		
		
		if s.command == "POST" and 'Content-Length' in s.headers:
			## read in POST vars
			p = s.rfile.read(int(s.headers['Content-Length'])).decode('utf8')
			p = str(p).split('&')
			
			for i in range(len(p)):
				a = p[i].split('=', 1)
				if a and len(a) == 2:
					s.post[urllib.parse.unquote_plus(a[0])] = urllib.parse.unquote_plus(a[1])
				elif a:
					s.post[urllib.parse.unquote_plus(a[0])] = ""
			
		
		
		## save the whole url
		s.url = s.path
		
		## split the request string up into its parts
		r = re.match(r"^(.+?)(?:\?(.*?))?$", s.path)
		
		if not r:
			return do_500(s, "Unable to process your request")
			
		## save!
		s.path, s.querystr = r.groups()
		
		## Gimme dem GET vars
		if s.querystr:
			g = str(s.querystr).split('&')
			
			for i in range(len(g)):
				a = g[i].split('=', 1)
				if a and len(a) == 2:
					s.get[urllib.parse.unquote_plus(a[0])] = urllib.parse.unquote_plus(a[1])
				elif a:
					s.get[urllib.parse.unquote_plus(a[0])] = ""
			
		
		return s.dispatch()
	
	
	
	def dispatch(s):
		"""Respond to a GET request."""
		
		
		s.path = urllib.parse.unquote_plus(s.path)
		
		s.path = s.path.replace('../','').\
						replace('..\\','').\
						replace('./','').\
						replace('.\\','').\
						lstrip('/\\')
		
		
		## index page if referring to a directory
		if os.path.isdir(DOC_ROOT+s.path):
			if s.path and s.path[-1] not in ['/','\\']:
				s.path += '/'
			for ndx in DIR_INDX:
				if os.path.isfile(DOC_ROOT+s.path + ndx):
					s.path += ndx
					break
		
		
		## directory indexing
		if os.path.isdir(DOC_ROOT+s.path):
			if not conf.getboolean('httpd', 'indexing'):
				return s.e404()
			else:
				s.send_response(200)
				s.send_header("Content-type", "text/html;charset=utf-8")
				#s.send_header("Cache-Control", "no-cache, must-revalidate")
				#s.send_header("Pragma", "no-cache")
				s.end_headers()
				s.send('<h2>Directory Index</h2>')
				s.send('<div>Path: %s</div>'%(s.path,))
				s.send('<br />')
				for fi in os.listdir(DOC_ROOT+s.path):
					# dont show hidden files
					if fi[0] == '.': continue
					s.send('<a href="./%s">%s</a> - %s<br />'%(fi, fi, size_fmt(os.stat(DOC_ROOT+s.path+fi).st_size)))
				return
		
		
		## no hidden files for you
		fn = os.path.basename(s.path)
		if fn and fn[0] == '.':
			return s.e404()
		
		
		## execute a python file
		if RUN_PY and os.path.isfile(DOC_ROOT+s.path) and s.path[-3:] == '.py':
			
			
			with open(DOC_ROOT+s.path, 'r') as f:
				source = f.read()
			
			## attempt to compile the source and run it
			try:
				o = compile(source, DOC_ROOT+s.path, 'exec')
				exec(o)
			except:
				traceback.print_exc()
				return
			
			return
		
		
		## display a static file
		if os.path.isfile(DOC_ROOT+s.path):
			s.send_response(200)
			
			mime = mimetypes.guess_type(s.path)[0]
			
			if mime:
				s.send_header("Content-type", mime)
			else:
				s.send_header("Content-type", 'text/plain')
			
			# gather file information
			st = os.stat(DOC_ROOT+s.path)
			
			# send file size
			s.send_header("Content-Length", st.st_size)
			
			# send modification date RFC 2822
			#s.send_header("Last-Modified", strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime(st.st_mtime)))
			
			s.end_headers()
			with open(DOC_ROOT+s.path, 'br') as f:
				while True:
					b = f.read(1024)
					if not b: break
					s.wfile.write(b)
			return
		
		return s.e404()
	
	



if __name__ == "__main__":
	try:
		init()
	except:
		traceback.print_exc()
		input("Press enter to close")
