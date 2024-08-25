#!/usr/bin/python

import os
import urllib.request
import json
from platform import system
import sys
from datetime import datetime
import time
import readline
import socket
import ipaddress
import math
import random
import string
import psutil
import nmap

def slowprint(s, delay=1./400, newline=True):
    for c in s:
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(delay)
    if newline:
        sys.stdout.write('\n')
        sys.stdout.flush()

def ipinfo():
    while True:
        try:
            os.system("figlet scan ip")
            print(" ")
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
            slowprint("\033[1;36m =====================================")
            slowprint("\033[1;33m |          IP Information           |")
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
            print("\033[1;36m")
            os.system("figlet DNS Lookup")
            print(" ")
            domain = input("\033[1;33mEnter a domain name (e.g., example.com):\033[0m ")
            ip_address = socket.gethostbyname(domain)
            slowprint(f"\033[1;33mThe IP address for \033[1;91m{domain} \033[1;33mis: \033[1;91m{ip_address}\033[0m")

            print(" ")
            input("\033[1;33m [+] Press Enter To Continue [+]\033[0m")

            os.system("clear")

        except socket.gaierror:
            os.system("clear")
            try:
                slowprint(f"\033[1;91mError: \033[1;33mUnable to resolve the domain \033[1;91m{domain}\033[0m")
                print(" ")
                input("\033[1;33m [+] Press Enter To Retry [+]\033[0m")
                os.system("clear")
                continue  
            except KeyboardInterrupt:
                os.system("clear")
                return
        except KeyboardInterrupt:
            os.system("clear")
            return
        except Exception as e:
            os.system("clear")
            try:
                slowprint(f"\033[1;91mAn unexpected error occurred: \033[1;33m{e}\033[0m")
                print(" ")
                input("\033[1;33m [+] Press Enter To Retry [+]\033[0m")
                os.system("clear")
                continue  
            except KeyboardInterrupt:
                os.system("clear")
                return

def ip_to_subnets():
    while True:
        try:
            print("\033[1;36m")
            os.system("figlet Subnet Divider")
            print(" ")
            ip_input = input("\033[1;32mEnter an IP address (e.g., 10.1.1.0/24): \033[0m")
            network = ipaddress.IPv4Network(ip_input, strict=False)
            
            num_subnets = int(input("\033[1;32mEnter the number of subnets to create: \033[0m"))
            if num_subnets <= 0:
                raise ValueError("Number of subnets must be a positive integer.")

            new_prefix = network.prefixlen + math.ceil(math.log2(num_subnets))
            if new_prefix > 32:
                raise ValueError("The number of subnets exceeds the available address space.")

            num_possible_subnets = 2**(new_prefix - network.prefixlen)
            subnet_mask = ipaddress.IPv4Network(f"0.0.0.0/{new_prefix}").netmask

            slowprint(f"\n\033[1;32mTo create {num_subnets} subnets, the new subnet mask will be: \033[1;91m{subnet_mask}\033[0m")
            slowprint(f"\033[1;32mYou can create up to {num_possible_subnets} subnets with this configuration.\033[0m\n")

            table_color = "\033[1;35m"

            slowprint(table_color + "{:<10} {:<20} {:<20} {:<20} {:<20}".format("Subnet", "Network Address", "First Host", "Last Host", "Broadcast Address"))
            slowprint(table_color + "-" * 90)

            subnets = list(network.subnets(new_prefix=new_prefix))
            for i, subnet in enumerate(subnets, 1):
                first_ip = subnet.network_address + 1
                last_ip = subnet.broadcast_address - 1
                print(table_color + "{:<10} {:<20} {:<20} {:<20} {:<20}".format(i, str(subnet.network_address), str(first_ip), str(last_ip), str(subnet.broadcast_address)))

            print (" ")
            magas = input("\033[1;33m [+] Press Enter To Continue [+]\033[0m")
            os.system("clear")

        except ValueError as e:
            slowprint(f"\033[1;31mError: {e}\033[0m")
            slowprint("\033[1;31mPlease enter a valid IP address and subnet number.\033[0m")
            input("\n\033[1;33mPress Enter to try again...\033[0m")
            os.system("clear")
        except KeyboardInterrupt:
            os.system("clear")
            return
        except Exception as e:
            slowprint(f"\033[1;31mAn unexpected error occurred: {e}\033[0m")
            slowprint("\033[1;31mPlease enter a valid IP address and subnet number.\033[0m")
            input("\n\033[1;33mPress Enter to try again...\033[0m")
            os.system("clear")

def ip_to_binary():
    while True:
        try:
            print("\033[1;36m")
            os.system("figlet Ip to Binary")
            print(" ")
            ip_cidr = input("\033[1;33mPlease enter a IP address with CIDR notation (e.g., 192.168.2.22/24):\033[0m ")
            
            if '/' not in ip_cidr:
                os.system("clear")
                try:
                    slowprint("\033[1;91mError: \033[1;33mYou forgot to include the CIDR notation. Please try again.\033[0m")
                    input("\n\033[1;33m [+] Press Enter To Retry [+]\033[0m")
                    os.system("clear")
                    continue
                except KeyboardInterrupt:
                    os.system("clear")
                    return

            if is_valid_ip_cidr(ip_cidr):
                ip, cidr = ip_cidr.split('/')
                cidr = int(cidr)
                mask = cidr_to_subnet_mask(cidr)

                print(" ")
                slowprint(f"\033[1;33mOriginal value:\033[1;91m {ip}/{cidr}\033[0m")
                slowprint(f"\033[1;33mMask:\033[1;91m {mask}\033[0m")

                signed_ip_bin = signed_binary_ip(ip, cidr)
                ip_bin = ip_to_binary_func(ip)
                signed_mask_bin = signed_binary_mask(cidr)
                mask_bin = ip_to_binary_func(mask)

                slowprint(f"\033[1;33mSigned IP Binary:\033[1;91m {signed_ip_bin}\033[0m")
                slowprint(f"\033[1;33mIP Binary:\033[1;91m {ip_bin}\033[0m")

                slowprint(f"\033[1;33mSigned Mask Binary:\033[1;91m {signed_mask_bin}\033[0m")
                slowprint(f"\033[1;33mMask Binary:\033[1;91m {mask_bin}\033[0m")

                print(" ")
                input("\033[1;33m [+] Press Enter To Continue [+]\033[0m")
                os.system("clear")
            else:
                os.system("clear")
                try:
                    slowprint("\033[1;91mError: \033[1;33mInvalid IP address or CIDR notation. Please try again.\033[0m")
                    input("\n\033[1;33m [+] Press Enter To Retry [+]\033[0m")
                    os.system("clear")
                except KeyboardInterrupt:
                    os.system("clear")
                    return

        except KeyboardInterrupt:
            os.system("clear")
            return

def is_valid_ip_cidr(ip_cidr):
    try:
        ipaddress.ip_interface(ip_cidr)
        return True
    except ValueError:
        return False

def cidr_to_subnet_mask(cidr):
    return str(ipaddress.IPv4Network(f'0.0.0.0/{cidr}').netmask)

def ip_to_binary_func(ip):
    return '.'.join(format(int(octet), '08b') for octet in ip.split('.'))

def signed_binary_ip(ip, cidr):
    binary_ip = ip_to_binary_func(ip).split('.')
    full_octets = cidr // 8
    remaining_bits = cidr % 8
    for i in range(4):
        if i < full_octets:
            binary_ip[i] = binary_ip[i]
        else:
            binary_ip[i] = binary_ip[i][:remaining_bits]
    return '.'.join(binary_ip)

def signed_binary_mask(cidr):
    mask = cidr_to_subnet_mask(cidr)
    return signed_binary_ip(mask, cidr)

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
            print("\033[1;36m")
            os.system("figlet Password Generator")
            print(" ")

            length = int(input("\033[1;32mEnter the length of the password (1-75): \033[0m"))
            if length < 1 or length > 75:
                raise ValueError("Length must be between 1 and 75.")
            
            use_uppercase = input("\033[1;32mInclude uppercase letters? (y/n): \033[0m").strip().lower() == 'y'
            use_lowercase = input("\033[1;32mInclude lowercase letters? (y/n): \033[0m").strip().lower() == 'y'
            use_special = input("\033[1;32mInclude special characters? (y/n): \033[0m").strip().lower() == 'y'

            password = generate_password(length, use_uppercase, use_lowercase, use_special)
            slowprint(f"\033[1;32mGenerated Password: \033[1;91m{password}\033[0m")
            
            print(" ")
            input("\033[1;33m [+] Press Enter To Continue [+]\033[0m")
            os.system("clear")
        
        except ValueError as e:
            os.system("clear")
            try:
                slowprint(f"\033[1;31mError: {e}\033[0m")
                print(" ")
                input("\033[1;33m [+] Press Enter To Continue [+]\033[0m")
                os.system("clear")
            except KeyboardInterrupt:
                os.system("clear")
                return
        
        except KeyboardInterrupt:
            os.system("clear")
            return

        except Exception as e:
            os.system("clear")
            try:
                slowprint(f"\033[1;31mAn unexpected error occurred: {e}\033[0m")
                print(" ")
                input("\033[1;33m [+] Press Enter To Continue [+]\033[0m")
                os.system("clear")
            except KeyboardInterrupt:
                os.system("clear")
                return

def port_scanner():
    while True:
        try:
            print("\033[1;36m")
            os.system("figlet Port Scanner")
            print(" ")

            target = input("\033[1;32mEnter the target IP address or hostname: \033[0m")
            port_range = input("\033[1;32mEnter the port range to scan (e.g., '20-80'): \033[0m")

            nm = nmap.PortScanner()
            slowprint(f"\n\033[1;34mScanning {target} for open ports in range {port_range}...\033[0m")

            nm.scan(target, port_range)
            
            for host in nm.all_hosts():
                slowprint(f"\n\033[1;32mHost: \033[1;91m{host} ({nm[host].hostname()})\033[0m")
                slowprint(f"\033[1;32mState: \033[1;91m{nm[host].state()}\033[0m")

                for protocol in nm[host].all_protocols():
                    slowprint(f"\033[1;32mProtocol: \033[1;91m{protocol}\033[0m")

                    ports = nm[host][protocol].keys()
                    for port in sorted(ports):
                        port_state = nm[host][protocol][port]['state']
                        slowprint(f"\033[1;32mPort: \033[1;91m{port}\t\033[1;32mState: \033[1;91m{port_state}\033[0m")

            print(" ")
            input("\033[1;33m [+] Press Enter To Continue [+]\033[0m")
            os.system("clear")

        except Exception as e:
            os.system("clear")
            slowprint(f"\033[1;31mError occurred: {str(e)}\033[0m")
            print(" ")
            input("\033[1;33m [+] Press Enter To Continue [+]\033[0m")
            os.system("clear")
        
        except KeyboardInterrupt:
            os.system("clear")
            return

def whois_lookup():
    while True:
        try:
            print("\033[1;36m")
            os.system("figlet WHOIS Lookup")
            print(" ")

            domain = input("\033[1;32mEnter a domain to look up: \033[0m")

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("whois.iana.org", 43))
            s.send(f"{domain}\r\n".encode())

            response = s.recv(4096).decode()
            s.close()

            slowprint(f"\033[1;91m{response}\033[0m")
            magas = input("\033[1;33m [+] Press Enter To Continue [+]\033[0m")

            os.system("clear")
            if magas == "":
                continue  
            else:
                break

        except KeyboardInterrupt:
            os.system("clear")
            return
        except Exception as e:
            os.system("clear")
            try:
                slowprint(f"\033[1;31mAn error occurred: {str(e)}\033[0m")
                print(" ")
                input("\033[1;33m [+] Press Enter To Continue [+]\033[0m")
                os.system("clear")
            except KeyboardInterrupt:
                os.system("clear")
                return

def format_bytes(size):
    # 2**10 = 1024
    power = 1024
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

def network_monitor():
    while True:
        try:
            os.system("clear")
            
            total_sent = 0
            total_recv = 0

            initial_value = psutil.net_io_counters()
            old_value = initial_value
            
            while True:
                new_value = psutil.net_io_counters()
                sent = new_value.bytes_sent - old_value.bytes_sent
                recv = new_value.bytes_recv - old_value.bytes_recv
                total_sent += sent
                total_recv += recv
                
                old_value = new_value

                print("\033[2J\033[H", end="")
                print("\033[1;33m [+] Press Ctrl+C to stop monitoring")
                print("\033[1;32m")
                print(f"\033[1;34mNetwork Monitoring:\033[0m")
                print(f"\033[1;32mTotal Bytes Sent: \033[1;91m{format_bytes(total_sent)}\033[0m")
                print(f"\033[1;32mTotal Bytes Received: \033[1;91m{format_bytes(total_recv)}\033[0m")
                print(f"\033[1;32mPackets Sent: \033[1;91m{new_value.packets_sent - initial_value.packets_sent}\033[0m")
                print(f"\033[1;32mPackets Received: \033[1;91m{new_value.packets_recv - initial_value.packets_recv}\033[0m")
                print(f"\033[1;32mErrors In: \033[1;91m{new_value.errin - initial_value.errin}\033[0m")
                print(f"\033[1;32mErrors Out: \033[1;91m{new_value.errout - initial_value.errout}\033[0m")
                print(f"\033[1;32mDropped Packets In: \033[1;91m{new_value.dropin - initial_value.dropin}\033[0m")
                print(f"\033[1;32mDropped Packets Out: \033[1;91m{new_value.dropout - initial_value.dropout}\033[0m")
                
                time.sleep(1)

        except KeyboardInterrupt:
            slowprint("\n\033[1;31m Monitoring stopped.\033[0m")
            print("")
            try:
                magas = input("\033[1;33m [+] Press Enter to restart or Ctrl+C to return [+] \033[0m")
                if magas == "":
                    continue  
            except KeyboardInterrupt:
                break  

    os.system("clear")
    return

def cidr_to_mask(cidr_input):
    try:
        cidr = int(cidr_input)
    except ValueError:
        return "Error: Invalid input. Please enter a number between 0 and 32."

    if cidr > 32 or cidr < 0:
        return "Error: CIDR value must be between 0 and 32."

    mask = []
    y = 0
    z = [1] * cidr

    for i in range(len(z)):
        math = i % 8
        if math == 0:
            if i >= 8:
                mask.append(y)
                y = 0
        y += pow(2, 7 - math)
    mask.append(y)
    [mask.append(0) for _ in range(4 - len(mask))]
    mask = ".".join([str(i) for i in mask])
    return mask

def run_cidr_to_mask():
    try:
        while True:
            os.system("clear")  
            print("\033[1;36m")
            os.system("figlet cidr to Mask")
            print(" ")
            cidr_input = input("\033[1;32mEnter a CIDR value (e.g., 24) or press Enter to exit: \033[0m")
            
            if not cidr_input:
                break
            
            mask = cidr_to_mask(cidr_input)
            
            if "Error" in mask:
                slowprint(f"\033[1;31m{mask}\033[0m")
            else:
                slowprint(f"\033[1;32mThe subnet mask for CIDR /{cidr_input} is: \033[1;91m{mask}\033[0m")
            
            print(" ")
            input("\033[1;33m [+] Press Enter To Continue [+]\033[0m")

    except KeyboardInterrupt:
        os.system("clear")
        return

def mask_to_cidr(mask):
    try:
        binary_str = ''.join([bin(int(x)).lstrip('0b').zfill(8) for x in mask.split('.')])
    except ValueError:
        return "Error: Invalid subnet mask format."

    if len(mask.split('.')) != 4 or any(int(octet) > 255 for octet in mask.split('.')):
        return "Error: Subnet mask must be in the format X.X.X.X with each octet between 0 and 255."

    cidr = str(binary_str.count('1'))
    
    if int(cidr) > 32 or int(cidr) < 0:
        return "Error: Subnet mask results in an invalid CIDR value."

    return cidr

def run_mask_to_cidr():
    try:
        while True:
            os.system("clear")  
            print("\033[1;36m")
            os.system("figlet mask to cidr")
            print(" ")
            mask_input = input("\033[1;32mEnter a subnet mask (e.g., 255.255.255.0) or press Enter to exit: \033[0m")

            if not mask_input:
                break
            
            cidr = mask_to_cidr(mask_input)
            
            if "Error" in cidr:
                slowprint(f"\033[1;31m{cidr}\033[0m")
            else:
                slowprint(f"\033[1;32mThe CIDR notation for subnet mask {mask_input} is: \033[1;91m/{cidr}\033[0m")
            
            print(" ")
            input("\033[1;33m [+] Press Enter To Continue [+]\033[0m")

    except KeyboardInterrupt:
        os.system("clear")
        return

def binary_to_ip(binary):
    octets = binary.split('.')
    ip = '.'.join(str(int(octet, 2)) for octet in octets)
    return ip

def is_valid_binary(binary):
    octets = binary.split('.')
    if len(octets) != 4:
        return False
    for octet in octets:
        if len(octet) != 8 or not all(bit in '01' for bit in octet):
            return False
    return True

def run_binary_to_ip():
    print("\033[1;36m")
    os.system("figlet Binary to IP")

    try:
        while True:
            print(" ")
            binary_input = input("Enter a binary IP (e.g., 11000000.10101000.00000001.00000001) or press Enter to exit: ")
            
            if not binary_input:
                break
            
            if is_valid_binary(binary_input):
                ip = binary_to_ip(binary_input)
                slowprint(f"The IP address for binary {binary_input} is: {ip}")
            else:
                slowprint("Error: Invalid binary IP format. Please enter in the format 8.8.8.8, with each octet as an 8-bit binary number.")

            print(" ")
            input("\033[1;33m [+] Press Enter To Continue [+]")

        os.system("clear")

    except KeyboardInterrupt:
        os.system("clear")
        return


def ipv4_to_ipv6(ipv4_address):
    try:
        ipv4 = ipaddress.IPv4Address(ipv4_address)
        ipv6 = ipaddress.IPv6Address('::ffff:' + str(ipv4))
        return str(ipv6)
    except ipaddress.AddressValueError:
        return "Invalid IPv4 address"

def ipv6_to_ipv4(ipv6_address):
    try:
        ipv6 = ipaddress.IPv6Address(ipv6_address)
        if ipv6.ipv4_mapped:
            return str(ipv6.ipv4_mapped)
        else:
            return "IPv6 address does not map to an IPv4 address"
    except ipaddress.AddressValueError:
        return "Invalid IPv6 address"

def validate_ip(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def run_ipv4_to_ipv6():
    while True:
        try:
            print("\033[1;36m")
            os.system("figlet ipv4 to ipv6")
            print(" ")
            ipv4_address = input("Enter an IPv4 address: ")
            if ipv4_address == "":
                continue

            ipv4 = ipaddress.IPv4Address(ipv4_address) 

            ipv6_address = ipaddress.IPv6Address('::ffff:' + ipv4_address)
            ipv6_compressed = str(ipv6_address)
            ipv6_expanded_short = ipv6_address.exploded
            ipv6_expanded_full = ipv6_expanded_short.replace('0000', '0')

            print(" ")
            slowprint(f"IPV6 Compressed: {ipv6_compressed}")
            slowprint(f"IPV6 Expanded (Shortened): {ipv6_expanded_full}")
            slowprint(f"IPV6 Expanded: {ipv6_expanded_short}")
            print(" ")
            input("\033[1;33m [+] Press Enter To Continue [+]")
            os.system("clear")
        except ipaddress.AddressValueError:
            try:
                print(" ")
                slowprint("Invalid IPv4 address")
                print(" ")
                input("\033[1;33m [+] Press Enter To Continue [+]")
                os.system("clear")
            except KeyboardInterrupt:
                os.system("clear")
                return
        except KeyboardInterrupt:
            os.system("clear")
            return

def run_ipv6_to_ipv4():
    while True:
        try:
            print("\033[1;36m")
            os.system("figlet ipv6 to ipv4")
            print(" ")
            ipv6_address = input("Enter an IPv6 address: ")
            if ipv6_address == "":
                continue

            ipv6 = ipaddress.IPv6Address(ipv6_address)

            ipv4_mapped = ipv6.ipv4_mapped
            if ipv4_mapped:
                slowprint(f"IPv4 address: {ipv4_mapped}")
            else:
                slowprint("This IPv6 address does not map to an IPv4 address.")
            
            print(" ")
            input("\033[1;33m [+] Press Enter To Continue [+]")
            os.system("clear")
        except ipaddress.AddressValueError:
            try:
                slowprint("Invalid IPv6 address")
                print(" ")
                input("\033[1;33m [+] Press Enter To Continue [+]")
                os.system("clear")
            except KeyboardInterrupt:
                os.system("clear")
                return
        except KeyboardInterrupt:
            os.system("clear")
            return

def ipv4_subnet_calculator():
    while True:
        try:
            print("\033[1;36m")
            os.system("figlet IPv4 Subnet Calculator")
            print(" ")
            ipv4_input = input("Enter an IPv4 address with CIDR (e.g., 192.0.3.171/27): ")
            print(" ")
            if ipv4_input == "":
                continue

            network = ipaddress.IPv4Network(ipv4_input, strict=False)
            ip = ipaddress.IPv4Address(ipv4_input.split('/')[0])

            netmask = network.netmask
            network_address = network.network_address
            broadcast_address = network.broadcast_address
            host_min = network_address + 1
            host_max = broadcast_address - 1
            num_hosts = network.num_addresses
            ipv6_repr = ipaddress.IPv6Address('2002::' + str(ip))
            ptr_rr_name = ip.reverse_pointer

            slowprint(f"\033[1;33mAddress:    \033[1;91m {ip}/{network.prefixlen}")
            slowprint(f"\033[1;33mNetmask:    \033[1;91m {netmask} = {network.prefixlen}")
            slowprint(f"\033[1;33mNetwork:    \033[1;91m {network_address}/{network.prefixlen}")
            slowprint(f"\033[1;33mHostMin:    \033[1;91m {host_min}")
            slowprint(f"\033[1;33mHostMax:    \033[1;91m {host_max}")
            slowprint(f"\033[1;33mBroadcast:  \033[1;91m {broadcast_address}")
            slowprint(f"\033[1;33mHosts/Net:  \033[1;91m {num_hosts}")
            slowprint(f"\033[1;33mIPv6 repr:  \033[1;91m {ipv6_repr}")
            slowprint(f"\033[1;33mPTR RR name:\033[1;91m {ptr_rr_name}")
            slowprint(f"\033[1;33mIP version: \033[1;91m {ip.version}")
            print(" ")
            input("\033[1;33m [+] Press Enter To Continue [+]\033[0m")
            os.system("clear")
        
        except ValueError as e:
            os.system("clear")
            try:
                slowprint(f"Error: {e}")
                print(" ")
                input("\033[1;33m [+] Press Enter To Retry [+]")
                os.system("clear")
            except KeyboardInterrupt:
                os.system("clear")
                return

        except KeyboardInterrupt:
            os.system("clear")
            return

        except Exception as e:
            os.system("clear")
            try:
                slowprint(f"An unexpected error occurred: {e}")
                print(" ")
                input("\033[1;33m [+] Press Enter To Retry [+]")
                os.system("clear")
            except KeyboardInterrupt:
                os.system("clear")
                return

def ipv6_subnet_calculator():
    while True:
        try:
            print("\033[1;36m")
            os.system("figlet IPv6 Subnet Calculator")
            print(" ")
            ipv6_input = input("\033[1;33mEnter an IPv6 address with CIDR (e.g., 2001:db8::/32):\033[0m ")
            if ipv6_input == "":
                continue

            network = ipaddress.IPv6Network(ipv6_input, strict=False)
            ip = ipaddress.IPv6Address(ipv6_input.split('/')[0])

            netmask = network.prefixlen
            network_address = network.network_address
            broadcast_address = network.broadcast_address
            host_min = network_address + 1
            host_max = broadcast_address - 1
            num_hosts = network.num_addresses
            ipv4_repr = ip.ipv4_mapped if ip.ipv4_mapped else "No IPv4 representation"
            ptr_rr_name = ip.reverse_pointer

            print(f"\033[1;33mAddress:    \033[1;91m {ip}/{netmask}")
            print(f"\033[1;33mNetmask:    \033[1;91m {network.netmask} = {netmask}")
            print(f"\033[1;33mNetwork:    \033[1;91m {network_address}/{netmask}")
            print(f"\033[1;33mHostMin:    \033[1;91m {host_min}")
            print(f"\033[1;33mHostMax:    \033[1;91m {host_max}")
            print(f"\033[1;33mBroadcast:  \033[1;91m {broadcast_address}")
            print(f"\033[1;33mHosts/Net:  \033[1;91m {num_hosts}")
            print(f"\033[1;33mIPv4 repr:  \033[1;91m {ipv4_repr}")
            print(f"\033[1;33mPTR RR name:\033[1;91m {ptr_rr_name}")
            print(f"\033[1;33mIP version: \033[1;91m {ip.version}")
            print(" ")
            input("\033[1;33m [+] Press Enter To Continue [+]\033[0m")
            os.system("clear")
        
        except ValueError as e:
            os.system("clear")
            try:
                slowprint(f"Error: {e}")
                print(" ")
                input("\033[1;33m [+] Press Enter To Retry [+]")
                os.system("clear")
            except KeyboardInterrupt:
                os.system("clear")
                return

        except KeyboardInterrupt:
            os.system("clear")
            return

        except Exception as e:
            os.system("clear")
            try:
                slowprint(f"An unexpected error occurred: {e}")
                print(" ")
                input("\033[1;33m [+] Press Enter To Retry [+]")
                os.system("clear")
            except KeyboardInterrupt:
                os.system("clear")
                return

def about():
    try:
        os.system("clear")
        print ("\033[1;32m\007\n")
        os.system("figlet Sys Tools")
        print("")
        slowprint ("\033[1;91m -----------------------------------------------")
        slowprint ("\033[1;33m" + "         [+] Tool Name     =>\033[1;36m" + " Sys Tools")
        slowprint ("\033[1;33m" + "         [+] Author        =>\033[1;36m" + " fruitsaladchan ")
        slowprint ("\033[1;33m" + "         [+] Latest Update =>\033[1;36m" + " 25/8/2024")
        slowprint ("\033[1;33m" + "         [+] Github        =>\033[1;36m" + " Github.com/fruitsaladchan")
        slowprint ("\033[1;91m -----------------------------------------------")
        print(" ")
        magas = input("\033[1;33m [+] Press Enter To Continue [+]")
        os.system("clear")
        return

    except KeyboardInterrupt:
        os.system("clear")
        return

def ext():
    slowprint ("\033[1;36m ==============================================")
    slowprint ("\033[1;33m |     Thanks For Using Sys Tools             |")
    slowprint ("\033[1;36m ==============================================")
    print(" ")
    exit()

def main():
    while True:
        try:
            os.system("clear")
            print("\033[1;36m")
            os.system("figlet Sys Tools")
            slowprint(" ")

            column1 = [
                "\033[1;33m [ 1  ]\033[1;91m Scan IP Address",
                "\033[1;33m [ 2  ]\033[1;91m DNS Lookup",
                "\033[1;33m [ 3  ]\033[1;91m ipv4 Subnet divider",
                "\033[1;33m [ 4  ]\033[1;91m IP to Binary",
                "\033[1;33m [ 5  ]\033[1;91m Binary to IP",
                "\033[1;33m [ 6  ]\033[1;91m Generate Password",
                "\033[1;33m [ 7  ]\033[1;91m Port Scanner",
                "\033[1;33m [ 8  ]\033[1;91m WHOIS Lookup",
            ]

            column2 = [
                "\033[1;33m [ 9  ]\033[1;91m Network Monitor",
                "\033[1;33m [ 10 ]\033[1;91m IPv4 to IPv6",  
                "\033[1;33m [ 11 ]\033[1;91m IPv6 to IPv4", 
                "\033[1;33m [ 12 ]\033[1;91m CIDR to Mask",
                "\033[1;33m [ 13 ]\033[1;91m Mask to CIDR",
                "\033[1;33m [ 14 ]\033[1;91m ipv4 subnet Calculator",
                "\033[1;33m [ 15 ]\033[1;91m ipv6 subnet Calculator",
                "\033[1;33m [ 16 ]\033[1;91m About This Tool",

            ]

            for i in range(len(column1)):
                slowprint(f"{column1[i]:<50} {column2[i]}")

            print("     ")
            slowprint("\033[1;33m [ 0  ]\033[1;91m Exit")
            print("     ")

            option = input("\033[1;36m [+] SysTools >> \033[1;32m")
            if option == "1":
                os.system("clear")
                ipinfo()

            elif option == "2":
                os.system("clear")
                dns_lookup()

            elif option == "3":
                os.system("clear")
                ip_to_subnets()

            elif option == "4":
                os.system("clear")
                ip_to_binary()

            elif option == "5":
                os.system("clear")
                run_binary_to_ip()

            elif option == "6":
                os.system("clear")
                password_generator()

            elif option == "7":
                os.system("clear")
                port_scanner()

            elif option == "8":
                os.system("clear")
                whois_lookup()

            elif option == "9":
                os.system("clear")
                network_monitor()

            elif option == "10":
                os.system("clear")
                run_ipv4_to_ipv6()

            elif option == "11":
                os.system("clear")
                run_ipv6_to_ipv4()

            elif option == "12":
                os.system("clear")
                run_cidr_to_mask()

            elif option == "13":
                os.system("clear")
                run_mask_to_cidr()

            elif option == "14":
                os.system("clear")
                ipv4_subnet_calculator()

            elif option == "15":
                os.system("clear")
                ipv6_subnet_calculator()

            elif option == "16":
                os.system("clear")
                about()

            elif option == "0":
                os.system("clear")
                ext()

            else:
                print(" ")
                slowprint("\033[1;91m Enter Correct Number!!!")
                time.sleep(1)
                os.system("clear")

        except KeyboardInterrupt:
            os.system("clear")
            slowprint ("\033[1;36m ==============================================")
            slowprint ("\033[1;33m |      Thanks For Using Sys Tools            |")
            slowprint ("\033[1;36m ==============================================")
            print(" ")
            sys.exit()

if __name__ == "__main__":
    main()
