import re
import time
import requests
from requests.auth import HTTPBasicAuth
import subprocess
import urllib.request


def ipinfo_lookup(handler, ip_list):

    print("Performing IP lookup on IPInfo...")
    processed_ip_list = []
    total_ips = len(ip_list)

    start_time = time.time()
    
    for index, ip in enumerate(ip_list, start=1):
        ip_info = handler.getDetails(ip)
        
        ip_address = ip_info.ip
        
        try:
            country = ip_info.country
        except:
            country = "NONE"

        try:
            organization = ip_info.org.split(' ',1)[1].upper()
        except:
            organization = "NONE"

        try:
            hostname = ip_info.hostname
        except:
            hostname = "NONE"

        processed_ip = {'IP ADDRESS':str(ip_address), 'COUNTRY':str(country), 'ORGANIZATION':str(organization), 'HOSTNAME':str(hostname)}
        processed_ip_list.append(processed_ip)

        print(f"\rProcessing {index}/{total_ips} IP addresses", end="", flush=True)

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"\nLookup complete. Elapsed time: {elapsed_time:.2f} seconds.\n")

    return processed_ip_list


def xforce_lookup(api_url, api_key, api_pw, ip_list):
    print("Performing IP lookup on IBM X-Force...")
    processed_ip_list = []
    total_ips = len(ip_list)

    start_time = time.time()

    for index, ip in enumerate(ip_list, start=1):

        exchange = f"ipr/{ip}"
        headers = {
            "Content-Type": "application/json",
        }

        response = requests.get(
            f"{api_url}{exchange}",
            headers=headers,
            auth=HTTPBasicAuth(api_key, api_pw)
        )

        if response.status_code == 200:
            data = response.json()

            ip_address = data.get('ip')

            try:
                country = data.get('geo')['country']
            except:
                country = "NONE"

            try:
                subnet = str(data.get('subnets'))
                organization_match = re.search(r"'company':\s*'(?P<org>.*?)'", subnet, re.IGNORECASE)
                if organization_match:
                    organization = organization_match.group('org')
                else:
                    organization = "NONE"
            except:
                organization = "NONE"

            risk_rating = (data.get("score"))

            category_raw = data.get('cats')
            if category_raw:
                category_key = str(list(category_raw.keys())[0])
                category_value = category_raw[category_key]
                category = f"{category_key} - {category_value}"
            else:
                category = "UNSUSPICIOUS"
            
            processed_ip = {'IP ADDRESS':str(ip_address), 'COUNTRY':str(country).upper(), 'ORGANIZATION':str(organization), 
                            'RISK RATING':str(risk_rating), 'CATEGORY':category.upper()}
            processed_ip_list.append(processed_ip)

        else:
            print(f"Error: {response.status_code}")
        
        print(f"\rProcessing {index}/{total_ips} IP addresses", end="", flush=True)

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"\nLookup complete. Elapsed time: {elapsed_time:.2f} seconds.\n")

    return processed_ip_list


def organization_parser(processed_ip_list, organization_keyword, source):

    print("Performing keyword parsing...")

    organization_keyword_list = organization_keyword.split(' ')
    output_list = []
    organization_keyword_counter = 0

    if organization_keyword_list[0] == "-":

        for ip in processed_ip_list:

            if source == "ibm_xforce":

                ip_address = ip['IP ADDRESS']
                country = ip['COUNTRY']
                organization = ip['ORGANIZATION']
                risk_rating = ip['RISK RATING']
                category = ip['CATEGORY']

                ip_output = f"{ip_address}[{country}:{organization}:{risk_rating}:{category}]"

            else:
                ip_address = ip['IP ADDRESS']
                country = ip['COUNTRY']
                organization = ip['ORGANIZATION']
                hostname = ip['HOSTNAME']

                ip_output = f"{ip_address}[{country}:{organization}:{hostname}]"
                
            output_list.append(ip_output)

        organization_keyword_counter += 1

    elif organization_keyword_list[0] == "not":

        for keyword in organization_keyword_list[1:]:

            for ip in processed_ip_list:
        
                if source == "ibm_xforce":
                    ip_address = ip['IP ADDRESS']
                    country = ip['COUNTRY']
                    organization = ip['ORGANIZATION']
                    risk_rating = ip['RISK RATING']
                    category = ip['CATEGORY']

                    if keyword not in organization.lower():
                        ip_output = f"{ip_address}[{country}:{organization}:{risk_rating}:{category}]"
                        output_list.append(ip_output)

                else: 
                    ip_address = ip['IP ADDRESS']
                    country = ip['COUNTRY']
                    organization = ip['ORGANIZATION']
                    hostname = ip['HOSTNAME']

                    if keyword not in organization.lower():
                        ip_output = f"{ip_address}[{country}:{organization}:{hostname}]"
                        output_list.append(ip_output)
            
            organization_keyword_counter += 1
    
    elif organization_keyword_list[0] != "not":

        for keyword in organization_keyword_list[0:]:

            for ip in processed_ip_list:

                if source == "ibm_xforce":
                    ip_address = ip['IP ADDRESS']
                    country = ip['COUNTRY']
                    organization = ip['ORGANIZATION']
                    risk_rating = ip['RISK RATING']
                    category = ip['CATEGORY']

                    if keyword in organization.lower():
                        ip_output = f"{ip_address}[{country}:{organization}:{risk_rating}:{category}]"
                        output_list.append(ip_output)
                
                else:
                
                    ip_address = ip['IP ADDRESS']
                    country = ip['COUNTRY']
                    organization = ip['ORGANIZATION']
                    hostname = ip['HOSTNAME']

                    if keyword in organization.lower():
                        ip_output = f"{ip_address}[{country}:{organization}:{hostname}]"
                        output_list.append(ip_output)
            
            organization_keyword_counter += 1
    
    else:
        print("ERROR-004 Invalid input. Use the '-h' for information on how to use the tool.")

    print("Keyword parsing complete.")
    output_dict = {'Keyword List': organization_keyword_list, 'Keyword Counter':organization_keyword_counter, 'Output List':output_list}
    return output_dict


def public_address_parser(ip_address):
    private_match = re.compile(r'((^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^::1$)|(^[fF][cCdD])/)|([a-zA-Z])').match(ip_address)
    if private_match:
        return True
    else:
        return False
    

def netstat():

    print("Processing Netstat output...")

    ns_output = subprocess.check_output('netstat -n').decode('ascii').splitlines()
    ns_output_startline = ns_output[5:]

    ns_foreign_address_parser = [output[2] for output in map(str.split, ns_output_startline)]
    ns_address_list = []
    seen_foreign_addresses = set()

    for match in ns_foreign_address_parser:
        foreign_address_and_port = match.split(":")
        parsed_foreign_address = foreign_address_and_port[0]
        
        if public_address_parser(parsed_foreign_address) == False:

            if parsed_foreign_address not in seen_foreign_addresses:
                seen_foreign_addresses.add(parsed_foreign_address)
                ns_address_list.append(parsed_foreign_address)

    print("Done.")

    return ns_address_list


def osint_blacklist():

    print("\nUpdating IP address blacklist... ")

    blacklist_url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"

    try:
        get_blacklist = urllib.request.urlopen(blacklist_url).read().decode('utf-8')
        parsed_blacklist = [line.split() for line in get_blacklist.strip().split('\n') if line.strip() and not line.startswith('#')]
        cleaned_blacklist = [ip[0] for ip in parsed_blacklist]
        print("IP address blacklist updated.")
    except:
        cleaned_blacklist = []
        print("Error-003: Failed to update blacklist IP")

    return cleaned_blacklist