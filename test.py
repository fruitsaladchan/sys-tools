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

def ipinfo():
    while True:
        try:
            slowprint("Enter IP Address : ")
            ip = input("\033[1;32m ")
            if ip.strip() == "":
                return

            url = ("http://ip-api.com/json/")
            response = urllib.request.urlopen(url + ip)
            data = response.read()
            values = json.loads(data)
            os.system("clear")

            print ("\033[1;32m\007\n")
            os.system("figlet Sys Tools")
            slowprint("\033[1;36m =====================================")
            slowprint("\033[1;33m|            IP Information           |")
            slowprint("\033[1;36m =====================================")
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
            os.system("clear")
            os.system("figlet DNS Lookup")
            print(" ")
            slowprint("Enter a domain name (e.g., example.com): ")
            domain = input()
            ip_address = socket.gethostbyname(domain)
            slowprint(f"The IP address for {domain} is: {ip_address}")

            print (" ")
            magas = input("\033[1;33m [+] Press Enter To Continue [+]")

            os.system("clear")

        except socket.gaierror:
            slowprint(f"Error: Unable to resolve the domain {domain}.")
        except KeyboardInterrupt:
            os.system("clear")
            return
        except Exception as e:
            slowprint(f"An unexpected error occurred: {e}")

def ip_to_subnets():
    while True:
        try:
            os.system("clear")
            os.system("figlet IP to Subnet")
            print(" ")
            slowprint("Enter an IP address (e.g., 10.1.1.0/24): ")
            ip_input = input()
            network = ipaddress.IPv4Network(ip_input, strict=False)
            slowprint("Enter the number of subnets to create: ")
            num_subnets = int(input())
            if num_subnets <= 0:
                raise ValueError("Number of subnets must be a positive integer.")

            new_prefix = network.prefixlen + math.ceil(math.log2(num_subnets))
            if new_prefix > 32:
                raise ValueError("The number of subnets exceeds the available address space.")

            num_possible_subnets = 2**(new_prefix - network.prefixlen)
            subnet_mask = ipaddress.IPv4Network(f"0.0.0.0/{new_prefix}").netmask

            slowprint(f"\nTo create {num_subnets} subnets, the new subnet mask will be: {subnet_mask}")
            slowprint(f"You can create up to {num_possible_subnets} subnets with this configuration.\n")

            subnets = list(network.subnets(new_prefix=new_prefix))
            slowprint(f"{'Subnet':<10} {'Network Address':<20} {'First Host':<20} {'Last Host':<20} {'Broadcast Address':<20}")
            slowprint("-" * 90)
            for i, subnet in enumerate(subnets, 1):
                first_ip = subnet.network_address + 1
                last_ip = subnet.broadcast_address - 1
                slowprint(f"{i:<10} {str(subnet.network_address):<20} {str(first_ip):<20} {str(last_ip):<20} {str(subnet.broadcast_address):<20}")

            print (" ")
            magas = input("\033[1;33m [+] Press Enter To Continue [+]")

            os.system("clear")

        except ValueError as e:
            slowprint(f"Error: {e}")
        except KeyboardInterrupt:
            os.system("clear")
            return
        except Exception as e:
            slowprint(f"An unexpected error occurred: {e}")

def ip_to_binary():
    while True:
        try:
            os.system("clear")
            os.system("figlet Ip to Binary")
            print(" ")
            slowprint("Please enter a valid IP address: ")
            ip = input()
            if is_valid_ip(ip):
                slowprint(f"The binary representation of {ip} is: {ip_to_binary_func(ip)}")

                print (" ")
                magas = input("\033[1;33m [+] Press Enter To Continue [+]")
                os.system("clear")
            else:
                slowprint("Invalid IP address. Please try again.")

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
            os.system("clear")
            os.system("figlet Password Generator")
            print(" ")
            slowprint("Enter the length of the password (1-50): ")
            length = int(input())
            if length < 1 or length > 50:
                raise ValueError("Length must be between 1 and 50.")
            
            slowprint("Include uppercase letters? (y/n): ")
            use_uppercase = input().strip().lower() == 'y'
            slowprint("Include lowercase letters? (y/n): ")
            use_lowercase = input().strip().lower() == 'y'
            slowprint("Include special characters? (y/n): ")
            use_special = input().strip().lower() == 'y'

            password = generate_password(length, use_uppercase, use_lowercase, use_special)
            slowprint(f"Generated Password: {password}")
            
            print (" ")
            magas = input("\033[1;33m [+] Press Enter To Continue [+]")

            os.system("clear")
        
        except ValueError as e:
            slowprint(f"Error: {e}")
        except KeyboardInterrupt:
            os.system("clear")
            return
        except Exception as e:
            slowprint(f"An unexpected error occurred: {e}")

def about():
    try:
        os.system("clear")
        print ("\033[1;32m\007\n")
        os.system("figlet Sys Tool")
        time.sleep(2)
        slowprint ("\033[1;91m -----------------------------------------------")
        slowprint ("\033[1;33m" + "         [+] Tool Name     =>\033[1;36m" + " Sys Tools")
        slowprint ("\033[1;33m" + "         [+] Author        =>\033[1;36m" + " fruitsaladchan ")
        slowprint ("\033[1;33m" + "         [+] Latest Update =>\033[1;36m" + " 17/3/2023")
        slowprint ("\033[1;33m" + "         [+] GitHub        =>\033[1;36m" + " https://github.com/fruitSaladChan ")
        slowprint ("\033[1;91m -----------------------------------------------")
        print (" ")
        magas = input("\033[1;33m [+] Press Enter To Continue [+]")
        os.system("clear")

    except KeyboardInterrupt:
        os.system("clear")

def main_menu():
    while True:
        os.system("clear")
        print ("\033[1;32m\007\n")
        os.system("figlet Sys Tools")
        slowprint("\033[1;36m =====================================")
        slowprint("\033[1;33m|              MAIN MENU             |")
        slowprint("\033[1;36m =====================================")
        slowprint("\033[1;33m| \033[1;36m1.\033[1;33m  IP Information                      |")
        slowprint("\033[1;33m| \033[1;36m2.\033[1;33m  DNS Lookup                          |")
        slowprint("\033[1;33m| \033[1;36m3.\033[1;33m  IP to Subnets                       |")
        slowprint("\033[1;33m| \033[1;36m4.\033[1;33m  IP to Binary                        |")
        slowprint("\033[1;33m| \033[1;36m5.\033[1;33m  Password Generator                  |")
        slowprint("\033[1;33m| \033[1;36m6.\033[1;33m  About                               |")
        slowprint("\033[1;33m| \033[1;36m7.\033[1;33m  Exit                                |")
        slowprint("\033[1;36m =====================================")
        slowprint("\033[1;33m|\033[1;36m Please Enter Your Choice: ",)
        choice = input("\033[1;32m ")
        if choice == '1':
            ipinfo()
        elif choice == '2':
            dns_lookup()
        elif choice == '3':
            ip_to_subnets()
        elif choice == '4':
            ip_to_binary()
        elif choice == '5':
            password_generator()
        elif choice == '6':
            about()
        elif choice == '7':
            slowprint("Exiting... Bye!")
            time.sleep(2)
            sys.exit()
        else:
            slowprint("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()
