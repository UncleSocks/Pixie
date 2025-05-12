import re
import time
import requests
from requests.auth import HTTPBasicAuth
import csv

#A lite (stripped down) version of Pixie for IBM X-Force. 
#Add the API Authentication keys and password to the 'auth.txt' file, separated by a colon (:)
#Add the IP addresses you want to lookup to the 'ip.txt' file.
#To run Pixie Lite, execute the pixie_lite.py file.
#It will automatically export the output to the 'output.csv' file.
#Note: This does not perform any blacklist lookup.

def banner():
    
    banner = """
        ____  _      _      
        |  _ \(_)_  _(_) ___ 
        | |_) | \ \/ / |/ _ \\
        |  __/| |>  <| |  __/
        |_|   |_/_/\_\_|\___|lite
        IBM X-Force IP Reputation

    """

    return print(banner)


def public_address_parser(ip_address):
    private_match = re.compile(r'((^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^::1$)|(^[fF][cCdD])/)|([a-zA-Z])').match(ip_address)
    if private_match:
        return True
    else:
        return False
    

def xforce_lookup(api_url, api_key, api_pw, ip_list):
    
    print("Performing IP lookup on IBM X-Force...")
    processed_ip_list = []
    total_ips = len(ip_list)

    start_time = time.time()

    for index, ip in enumerate(ip_list, start=1):
        
        exchange = f"ipr/{ip}"
        headers = {
            "Content-Type":"application/json",
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

            try:
                risk_rating = data.get('score')
            except:
                risk_rating = "NONE"

            category_raw = data.get('cats')
            if category_raw:
                category_key = str(list(category_raw.keys())[0])
                category_value = category_raw[category_key]
                category = f"{category_key} - {category_value}%"
            else:
                category = "UNSUSPICIOUS"

            processed_ip = [str(ip_address), str(country).upper(), str(organization).upper(), 
                            str(risk_rating), str(category).upper()]
            
            processed_ip_list.append(processed_ip)

        else:
            print(f"ERROR: {response.status_code}")

        print(f"\rProcessing {index}/{total_ips} IP addresses", end="", flush=True)
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"\nLookup complete. Elapsed time: {elapsed_time:.2f} seconds.\n")

    return processed_ip_list


def xforce_connect():
    
    print("Connecting to IBM X-Force API...")
    
    api_url = "https://api.xforce.ibmcloud.com/"

    with open("auth.txt") as auth:
        auth_parser = auth.read().strip().split(':')
        api_key = auth_parser[0]
        api_pw = auth_parser[1]

    return api_url, api_key, api_pw


def wordlist_process():
    
    print("Parsing IP wordlist...")
    
    ip_list = []
    with open("ip.txt") as ip_wordlist:
        for ip in ip_wordlist:
            ip = ip.strip()
            if public_address_parser(ip) == False:
                ip_list.append(ip)

    return ip_list


def csv_output(processed_ip_list):
    
    with open(f'./output.csv', 'w', newline='') as csv_export:
        csv_writer = csv.writer(csv_export)
        csv_writer.writerow(['IP ADDRESS', 'COUNTRY', 'ORGANIZATION', 'RISK RATING', 'CATEGORY'])
        csv_writer.writerows(processed_ip_list)

    print("Successfully exported to a CSV file.")

    return


if __name__ == "__main__":

    banner()
    
    api_url, api_key, api_pw = xforce_connect()
    ip_list = wordlist_process()
    processed_ip_list = xforce_lookup(api_url, api_key, api_pw, ip_list)

    csv_output(processed_ip_list)
    print("Done.")
    time.sleep(5)