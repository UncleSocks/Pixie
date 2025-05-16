import re
import subprocess
import platform



def ip_parser(wordlist):

    print("Parsing IP address from the wordlist...")

    ip_list = []
    
    try:
        with open(wordlist) as ip_wordlist:
            for ip in ip_wordlist:
                ip = ip.strip()
                ip_list.append(ip)
    except:
        raise ValueError(f"ERR-IN01: File '{wordlist}' cannot be found. If the --wordlist option is not specified, Pixie uses the default 'ip.txt' file as its wordlist")
    
    total_ips = len(ip_list)
    print(f"Parsing complete. Captured {total_ips} IP addresses.\n")

    return ip_list


def netstat_ipv6_cleaner(ipv6):

    ipv6 = ipv6[1:].split("]")[0]
    return ipv6


def netstat_os_parse():

    operating_system = platform.system()

    if operating_system.upper() == "WINDOWS":
        ns_output = subprocess.check_output(['netstat', '-n']).decode('ascii').strip().split("\n")
        ns_output_startline = ns_output[5:]

        ns_foreign_address_parser = [output[2] for output in map(str.split, ns_output_startline)]

        return ns_foreign_address_parser
    
    elif operating_system.upper() == "LINUX":
        ns_output = subprocess.check_output(['netstat', '-tun']).decode('ascii').strip().split("\n")
        ns_output_startline = ns_output[2:]

        ns_foreign_address_parser = [output[4] for output in map(str.split, ns_output_startline)]

        return ns_foreign_address_parser


def netstat_parser():

    print("Processing Netstat output...")

    ns_foreign_address_parser = netstat_os_parse()
    ns_address_list = []
    seen_foreign_addresses = set()

    for foreign_address in ns_foreign_address_parser:
        
        if foreign_address.startswith("["):
            parsed_foreign_address = netstat_ipv6_cleaner(foreign_address)

        else:
            foreign_address_and_port = foreign_address.split(":")
            parsed_foreign_address = foreign_address_and_port[0]
        
        if not public_address_parser(parsed_foreign_address):
                
            if parsed_foreign_address not in seen_foreign_addresses:
                seen_foreign_addresses.add(parsed_foreign_address)
                ns_address_list.append(parsed_foreign_address)

    if not ns_address_list:
        raise ValueError(f"ERR-IN02: No foresign IP address was captured from netstat.")
    else:
        total_ips = len(ns_address_list)
        print(f"Done parsing IP addresses from Netstat. Captured {total_ips} IP addresses")
    
    return ns_address_list


def public_address_parser(ip_address):
    private_match = re.compile(r'((^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^::1$)|(^[fF][cCdD])/)|([a-zA-Z])').match(ip_address)
    return private_match