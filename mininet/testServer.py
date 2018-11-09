#server

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import os
import sys

#Custom HTTPRequest class
class testHTTPRequestHandler(BaseHTTPRequestHandler):
	#handle GET command
	def do_GET(self):
		print 'got a GET path:{0}'.format(self.path)
		try:
			if self.path.endswith('.html'):
				f = open(self.path)
				self.send_response(200)
				self.send_header('Content-type','text-html')
				self.wfile.write(f.read())
				f.close()
				return
		except IOError:
			self.send_error(404,'file not found')
		print 'response for {0}  send'.format(self.path)
def run():
	print "http server is starting..."
	server_address = (sys.argv[1],80)
	httpd = HTTPServer(server_address, testHTTPRequestHandler)
	print 'http server is running...'
	httpd.serve_forever()
if __name__ == '__main__':
	run()
