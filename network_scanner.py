#!/usr/bin/env python

from os import geteuid
from datetime import date
from pickle import load, dump
from scapy.all import ARP, Ether, srp
from optparse import OptionParser
from time import strftime, localtime, time
from colorama import Fore, Back, Style

status_color = {
	'+': Fore.GREEN,
	'-': Fore.RED,
	'*': Fore.YELLOW,
	':': Fore.CYAN,
	' ': Fore.WHITE,
}

def get_time():
	return strftime("%H:%M:%S", localtime())
def display(status, data):
	print(f"{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {get_time()}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}")

def display_clients(clients):
	print(f"{Fore.GREEN}IP{' '*18}MAC{Fore.WHITE}\n{'-'*37}{Fore.CYAN}")
	for client in clients:
		ip = client["ip"]
		mac = client["mac"]
		print(f"{ip:20}{mac}")
	print(Fore.RESET)

def get_arguments(*args):
	parser = OptionParser()
	for arg in args:
		parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
	return parser.parse_args()[0]

def check_root():
	return geteuid() == 0

def scan(ip, timeout=1):
	arp = ARP(pdst=ip)
	ether = Ether(dst="ff:ff:ff:ff:ff:ff")
	packet = ether / arp
	result = srp(packet, timeout=timeout, verbose=False)[0]
	clients = []
	for _, received in result:
		clients.append({"ip": received.psrc, "mac": received.hwsrc})
	return clients

if __name__ == "__main__":
	data = get_arguments(('-T', "--target", "target", "target/targets to scan (seperated by ',')"),
						 ('-t', "--timeout", "timeout", "timeout for response (default = 1 seconds)"),
						 ('-l', "--load", "load", "Load Targets from a file"),
						 ('-r', '--read', "read", "File to read a Previous Scan Result"),
						 ('-w', "--write", "write", "Dump the output to a File"))
	if data.read:
		try:
			with open(data.read, 'rb') as file:
				result = load(file)
		except FileNotFoundError:
			display('-', "File not Found!")
			exit(0)
		except:
			display('-', "Error in Reading the File")
			exit(0)
		for target, clients in result.items():
			display(':', f"Scan Result for Target = {target}")
			display_clients(clients)
			display(':', f"Total Clients Discovered = {Back.MAGENTA}{len(clients)}{Back.RESET}")
			print('\n')
		exit(0)
	if not check_root():
		display('-', f"This Program requires {Back.MAGENTA}root{Back.RESET} Privileges")
		exit(0)
	if not data.target:
		if not data.load:
			display('-', "Please specify a Target")
			exit(0)
		else:
			try:
				with open(data.load, 'r') as file:
					data.target = file.read().split('\n')
				data.target = [target for target in data.target if target != '']
			except FileNotFoundError:
				display('-', "File not Found!")
				exit(0)
			except:
				display('-', "Error in Reading the File")
				exit(0)
	else:
		data.target = data.target.split(',')
	if not data.timeout:
		display('*', "No Timeout specified!")
		display(':', f"Setting the Timeout to {Back.MAGENTA}1{Back.RESET} seconds")
		data.timeout = 1
	else:
		data.timeout = float(data.timeout)
	result = {}
	for target in data.target:
		display('+', f"Starting the Network Scan on {target}")
		t1 = time()
		clients = scan(target, timeout=data.timeout)
		t2 = time()
		result[target] = clients
		display('+', "Finished Scanning the Network\n")
		display_clients(clients)
		display(':', f"Total Clients Discovered = {Back.MAGENTA}{len(clients)}{Back.RESET}")
		display(':', f"Time Taken to Complete the Scan = {Back.MAGENTA}{t2-t1}{Back.RESET} seconds")
		print('\n')
	if data.write:
		if data.write == '':
			with open(get_time(), 'wb') as file:
				dump(result, file)
		else:
			with open(data.write, 'wb') as file:
				dump(result, file)