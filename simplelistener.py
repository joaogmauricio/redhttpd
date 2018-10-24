#!/usr/bin/python

import socket
import sys
from thread import *

class SimpleListener:

	def socketthread(self, conn):
		try:
			while True:
				data = conn.recv(1024)
				if data:
					print data,
					sys.stdout.flush()
				else:
					break
		except:
			pass

	def __init__(self, host, port):
		self.host = host
		self.port = port
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	def start(self):
		try:
			self.s.bind((self.host, self.port))
			self.s.listen(10)

			print 'Listening'

			conn, addr = self.s.accept()
			print 'Connected with ' + addr[0] + ':' + str(addr[1])

			start_new_thread(self.socketthread, (conn,))

			while 1:
		    		cmd = raw_input()
		        	if cmd == "exit" or cmd == "quit":
		            		break
		        	else:
		            		conn.send(cmd + '\n')

			conn.shutdown(1)
			conn.close()

		except socket.error as msg:
		    print 'Socket failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]

		finally:
			self.stop()

	def stop(self):
		print "Exiting Listener...\r\n"
		self.s.shutdown(1)
		self.s.close()
