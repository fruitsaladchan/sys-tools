#!/usr/bin/python

import os
import urllib.request
import json
from platform import system
import sys
from datetime import datetime
import time
import socket
import ipaddress
import math
import random
import string

def slowprint(s):
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(1. / 200)

def print_header(title):
    os.system("clear")
    slowprint("\033[1;36m =====================================")
    slowprint(f"\033[1;33m|{title:^36}|")
    slowprint("\033[1;36m =====================================")

def ipinfo():
    while True:
        try:
            print_header("IP Information")
            ip = input(" Enter IP Address : \033[1;32m ")
            if ip.strip() == "":
                return

            url = ("http://ip-api.com/json/")
            response = urllib.request.urlopen(url + ip)
            data = response.read()
            values = json.loads(data)
            os.system("clear")

            print ("\033[1;32m\007\n")
            os.system("figlet Sys Tools")
            print_header("IP Information")
            slowprint("\033[1;36m" + "\n IP          : \033[1;32m " + values['query'])
            slowprint("\033[1;36m" + " Status      : \033[1;32m " + values['status'])
            slowprint("\033[1;36m" + " Region      : \033[1;32m " + values['regionName'])
            slowprint("\033[1;36m" + " Country     : \033[1;32m " + values['country'])
            slowprint("\033[1;36m" + " Date & Time : \033[1;32m " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            slowprint("\033[1;36m" + " City        : \033[1;32m " + values['city'])
            slowprint("\033[1;36m" + " ISP         : \033[1;32m " + values['isp'])
            slowprint("\033[1;36m" + " Lat,Lon     : \033[1;32m " + str(values['lat']) + "," + str(values['lon']))
            slowprint("\033[1;36m" + " ZIPCODE     : \033[1;32m " + values['zip'])
            slowprint("\033[1;36m" + " TimeZone    : \033[1;32m " + values['timezone'])
            slowprint("\033[1;36m" + " AS          : \033[1;32m " + values['as'] + "\n")
            print (" ")
            slowprint("\033[1;36m =====================================")
            print (" ")
            
            magas = input("\033[1;33m [+] Press Enter To Continue [+]")

            os.system("clear")

        except KeyboardInterrupt:
            os.system("clear")
            return

def dns_lookup():
    while True:
        try:
            print_header("DNS Lookup")
            domain = input("Enter a domain name (e.g., example.com): ")
            ip_address = socket.gethostbyname(domain)
            print(f"The IP address for {domain} is: {ip_address}")

            magas = input("\033[1;33m [+] Press Enter To Continue [+]")

            os.system("clear")

        except socket.gaierror:
            print(f"Error: Unable to resolve the domain {domain}.")
        except KeyboardInterrupt:
            os.system("clear")
            return
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

def ip_to_subnets():
    while True:
        try:
            print_header("IP to Subnets")
            ip_input = input("Enter an IP address (e.g., 10.1.1.0/24): ")
            network = ipaddress.IPv4Network(ip_input, strict=False)
            num_subnets = int(input("Enter the number of subnets to create: "))
            if num_subnets <= 0:
                raise ValueError("Number of subnets must be a positive integer.")

            new_prefix = network.prefixlen + math.ceil(math.log2(num_subnets))
            if new_prefix > 32:
                raise ValueError("The number of subnets exceeds the available address space.")

            num_possible_subnets = 2**(new_prefix - network.prefixlen)
            subnet_mask = ipaddress.IPv4Network(f"0.0.0.0/{new_prefix}").netmask

            print(f"\nTo create {num_subnets} subnets, the new subnet mask will be: {subnet_mask}")
            print(f"You can create up to {num_possible_subnets} subnets with this configuration.\n")

            subnets = list(network.subnets(new_prefix=new_prefix))
            print(f"{'Subnet':<10} {'Network Address':<20} {'First Host':<20} {'Last Host':<20} {'Broadcast Address':<20}")
            print("-" * 90)
            for i, subnet in enumerate(subnets, 1):
                first_ip = subnet.network_address + 1
                last_ip = subnet.broadcast_address - 1
                print(f"{i:<10} {str(subnet.network_address):<20} {str(first_ip):<20} {str(last_ip):<20} {str(subnet.broadcast_address):<20}")

            magas = input("\033[1;33m [+] Press Enter To Continue [+]")

            os.system("clear")

        except ValueError as e:
            print(f"Error: {e}")
        except KeyboardInterrupt:
            os.system("clear")
            return
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

def ip_to_binary():
    while True:
        try:
            print_header("IP to Binary")
            ip = input("Please enter a valid IP address: ")
            if is_valid_ip(ip):
                print(f"The binary representation of {ip} is: {ip_to_binary_func(ip)}")
                magas = input("\033[1;33m [+] Press Enter To Continue [+]")
                os.system("clear")
            else:
                print("Invalid IP address. Please try again.")

        except KeyboardInterrupt:
            os.system("clear")
            return

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def ip_to_binary_func(ip):
    return '.'.join(format(int(octet), '08b') for octet in ip.split('.'))

def generate_password(length, use_uppercase, use_lowercase, use_special):
    characters = ""
    
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_special:
        characters += string.punctuation
    
    if not characters:
        raise ValueError("At least one character type must be selected.")
    
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def password_generator():
    while True:
        try:
            print_header("Generate Password")
            length = int(input("Enter the length of the password (1-50): "))
            if length < 1 or length > 50:
                raise ValueError("Length must be between 1 and 50.")
            
            use_uppercase = input("Include uppercase letters? (y/n): ").strip().lower() == 'y'
            use_lowercase = input("Include lowercase letters? (y/n): ").strip().lower() == 'y'
            use_special = input("Include special characters? (y/n): ").strip().lower() == 'y'

            password = generate_password(length, use_uppercase, use_lowercase, use_special)
            print(f"Generated Password: {password}")

            magas = input("\033[1;33m [+] Press Enter To Continue [+]")

            os.system("clear")
        
        except ValueError as e:
            print(f"Error: {e}")
        except KeyboardInterrupt:
            os.system("clear")
            return
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

def about():
    try:
        print_header("About This Tool")
        print ("\033[1;32m\007\n")
        os.system("figlet Sys Tool")
        time.sleep(2)
        slowprint ("\033[1;91m -----------------------------------------------")
        slowprint ("\033[1;33m" + "         [+] Tool Name     =>\033[1;36m" + " Sys Tools")
        slowprint ("\033[1;33m" + "         [+] Author        =>\033[1;36m" + " fruitsaladchan ")
        slowprint ("\033[1;33m" + "         [+] Latest Update =>\033[1;36m" + " 17/3/2023")
        slowprint ("\033[1;33m" + "         [+] Github        =>\033[1;36m" + " Github.com/fruitsaladchan")
        slowprint ("\033[1;91m -----------------------------------------------")
        magas = input("\033[1;33m [+] Press Enter To Continue [+]")
        os.system("clear")

    except KeyboardInterrupt:
        os.system("clear")
        return

def main_menu():
    os.system("clear")
    while True:
        print ("\033[1;32m\007\n")
        os.system("figlet Sys Tools")
        print_header("Main Menu")
        slowprint (" \033[1;33m[01] \033[1;36m IP Information ")
        slowprint (" \033[1;33m[02] \033[1;36m DNS Lookup ")
        slowprint (" \033[1;33m[03] \033[1;36m IP To Subnets ")
        slowprint (" \033[1;33m[04] \033[1;36m IP To Binary ")
        slowprint (" \033[1;33m[05] \033[1;36m Generate Password ")
        slowprint (" \033[1;33m[00] \033[1;31m Exit \n")

        option = input("\033[1;33m [+] Select Your Option -> \033[1;32m")

        if option == "1" or option == "01":
            ipinfo()
        elif option == "2" or option == "02":
            dns_lookup()
        elif option == "3" or option == "03":
            ip_to_subnets()
        elif option == "4" or option == "04":
            ip_to_binary()
        elif option == "5" or option == "05":
            password_generator()
        elif option == "0" or option == "00":
            os.system("clear")
            sys.exit()
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main_menu()
