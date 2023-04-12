# Network Scanner
A Python Program that scans the Network giving a list of IP Addresses and MAC Addresses of the devices connected to that Network.

## Requirements
Languange Used = Python3<br />
Modules/Packages used:
* os
* datetime
* pickle
* scapy
* optparse
* time
* colorama

## Input
The network_scanner.py takes the following arguments through the command that is used to run the Python Program:
* '-T', "--target" : target/targets to scan (seperated by ',')
* '-t', "--timeout" : timeout for response (default = 1 seconds)
* '-l', "--load" : Load Targets from a file
* '-r', "--read" : File to read a Previous Scan Result
* '-w', "--write" : Dump the output to a File

## Working
The program crafts a packet by stacking Ethernet Frame over the ARP Request and sends it to the broadcast address of the Network so that every device would receive that packet.<br />
It would wait for the time that was given in the arguments.<br />
After that delay, it would make a list of all the Devices that responded to the sent packet containing their IP Addresses and MAC Addresses and display that list on the screen. And then display the number of clients discovered and time taken to complete the scan.

### Note
This may not detect all the devices connected on the network.<br />
It depends upon the response of the device that receives the packet send by our program to the broadcast address of the Network.