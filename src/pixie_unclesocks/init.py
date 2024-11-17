import ipinfo
import maskpass
from argparse import ArgumentParser
from parser_modules.parsers import public_address_parser
from strings import pixie_logo

def arguments():

    argument_parser = ArgumentParser(description="Defender's mini IP address workflow. Enter the organization keyword/s for searching, use space as a separator for multiple keywords; prepend the 'NOT' keyword to negate the search. The '-' character will process all IP addresses in the list without any keyword.")
    argument_parser.add_argument("-w","--wordlist", help="Specify the location of the text file containing the IP addresses to be processed.")
    argument_parser.add_argument("-n", "--netstat", action="store_true", help="Uses 'netstat -n' to capture public IP addresses communicating with the host.")
    argument_parser.add_argument("-i", "--ioc", help="[Optional] Specify the location of the text file containing the blacklist. If not specified Pixie will use the Cisco Talos Intelligence blacklist.")
    argument_parser.add_argument("-o", "--output", help="[Optional] Specify the filename for the CSV file with the .csv extension.")
    argument_parser.add_argument("-s", "--source", help="Specify IP address lookup OSINT source. Use i for IPInfo and x for IBM X-Force")
    argument = argument_parser.parse_args()

    return argument


def ip_wordlist(wordlist_argument):

    print("Processing wordlist...")

    ip_list = []
    with open(wordlist_argument.wordlist) as ip_wordlist:
        for ip in ip_wordlist:
            ip = ip.strip()
            if public_address_parser(ip) == False:
                ip_list.append(ip)

    print("Done.\n")

    return ip_list


def blacklist_wordlist():
    
    print("\nParsing blacklist file...")
    parsed_wordlist_blacklist = []
    
    with open(arguments().ioc) as wordlist_blacklist:
        for entry in wordlist_blacklist:
            entry = entry.strip()
            parsed_wordlist_blacklist.append(entry)
    
    print("Parsing complete.\n")

    return parsed_wordlist_blacklist


def ip_init():

    pixie_logo()
    print("Connect to IPInfo.")

    access_token = maskpass.askpass("Enter token: ")
    try:
        print("Connecting to IPInfo...")
        handler = ipinfo.getHandler(access_token)
    except:
        print("ERROR-002: Cannot connect to IPInfo, make sure that you are connecting to the Internet.")
    print("Connected.")
    return handler


def xforce_init():

    pixie_logo()
    print("Connect to IBM X-Force.")

    api_url = "https://api.xforce.ibmcloud.com/"
    api_key = maskpass.askpass("Enter API Key: ")
    api_pw = maskpass.askpass("Enter API Password: ")
    
    return api_url, api_key, api_pw


def organization_keyword():
    
    organization_keyword = input("\nEnter organization keyword (e.g., Microsoft): ").lower()
    return organization_keyword