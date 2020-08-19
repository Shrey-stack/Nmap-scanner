#!/usr/bin/python3

import nmap
scanner= nmap.PortScanner();
print("Welcome to my simple nmap scanning tool")
print("." * 50)

p_address = input("Please enter your IP address you want to scan:")
print("The IP address you entered is : ", ip_address)
type(ip_address)

response = input("""\n Please enter the type of Scan you want to run
                1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive Scan \n""")
print("You have selected option: ", response)
if response=="1":
    print("Nmap version: ")
    scanner.scan(ip_address, '1-1024', "-v -sS")
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_address].state)
    print(scanner[ip_address]. all_protocols())
    print("Open Ports: ", scanner[ip_address] ["tcp"].keys())

elif response=="2":
    print("Nmap version: ")
    scanner.scan(ip_address, '1-1024', "-v -sU")
    scanner.scaninfo(())
    print("IP Status: ", scanner[ip_address].state)
    print(scanner[ip_address].all_protocols())
    print("Open Ports: ", scanner[ip_address]["udp"].keys())

elif response=="3":
    print("Nmap version: ")
    scanner.scan(ip_address, '1-1024', "-v -sS -sV -sC -A -O")
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_address].state)
    print(scanner[ip_address].all_protocols())
    print("Open Ports: ", scanner[ip_address]["tcp"].keys())

elif response>="4":
    print("Please enter a valid option")

