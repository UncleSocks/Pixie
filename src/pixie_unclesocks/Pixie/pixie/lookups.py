import time
import json
import urllib.request

from requests import request



class AbuseIpDbLookup:
    
    def __init__(self, api_key):
        self.api_key = api_key

    def abuse_api_check(self):
        
        print("\nTesting Abuse IP DB API connection...")
        
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept':'application/json',
            'Key':self.api_key
        }
        test_query = {'ipAddress':'8.8.8.8'}

        response = request(method='GET', url=url, headers=headers, params=test_query)

        if response.status_code == 200:
            print("Abuse IP DB connection test successful.")
            return
        
        else:
            raise ValueError(f"Failed to connect to Abuse IP DB. Returned status {response.status_code} with error: {response.text}.")

    

    def abuse_lookup(self, ip_list):

        print("Performing Abuse IP DB lookup...")
        processed_ip_list = []
        total_ips = len(ip_list)
        start_time = time.time()

        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept':'application/json',
            'Key':self.api_key
        }

        for index, ip in enumerate(ip_list, start=1):

            query_string = {
                'ipAddress':ip,
                'maxAgeInDays':'30'
            }

            response = request(method='GET', url=url, headers=headers, params=query_string)
            decoded_response = json.loads(response.text)
            is_public = bool(decoded_response['data'].get('isPublic'))

            if is_public:

                ip_address = decoded_response['data'].get('ipAddress')

                country_code = decoded_response['data'].get('countryCode', "NONE")

                hostnames = ", ".join(decoded_response['data']['hostnames'])
                if not hostnames:
                    hostnames = "NONE"

                domain = decoded_response['data'].get('domain', "NONE")
                isp = decoded_response['data'].get('isp', "NONE")

                abuse_raw_score = decoded_response['data'].get('abuseConfidenceScore')
                abuse_score = str(abuse_raw_score) + "%"

                total_reports = decoded_response['data'].get('totalReports', 0)
                last_reported_at = decoded_response['data'].get('lastReportedAt', "UNKNOWN")

            else:
                ip_address = ip
                country_code = "PRIVATE"
                hostnames = "NOT APPLICABLE"
                domain = "NOT APPLICABLE"
                isp = "NOT APPLICABLE"
                abuse_raw_score = 0
                abuse_score = 0
                total_reports = 0
                last_reported_at = "NOT APPLICABLE"

            processed_ip = {"IP Address":str(ip_address), "Country Code":str(country_code), "Hostnames":str(hostnames), "Domain":str(domain), "ISP":str(isp), "Raw Abuse Score":int(abuse_raw_score), \
                            "Abuse Score":str(abuse_score), "Total Reports":int(total_reports), "Last Reported At":str(last_reported_at)}
            processed_ip_list.append(processed_ip)

            print(f"\rProcessing {index}/{total_ips} IP addresses", end="", flush=True)

        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"\nLookup complete. Elapsed time: {elapsed_time:.2f} seconds.\n")

        return processed_ip_list
    


class BlacklistLookup:

    def __init__(self, blacklist_source):

        self.blacklist_source = blacklist_source

    def osint_blacklist(self):
        
        blacklist_url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
        print(f"Updating IP address blacklist from {blacklist_url}")

        try:
            get_blacklist = urllib.request.urlopen(blacklist_url).read().decode('utf-8')
            parsed_blacklist = [ip.split()[0] for ip in get_blacklist.strip().split("\n") if ip.strip() and not ip.startswith('#')]
            print("OSINT blacklist successfully updated.")

        except:
            parsed_blacklist = []
            print("ERR-IN03: OSINT blacklist failed to update.")

        return parsed_blacklist


    def local_blacklist(self):

        print("Parsing local blacklist file...")
        parsed_local_blacklist = []

        try:
            with open(self.blacklist_source) as blacklist_wordlist:
                for ip in blacklist_wordlist:
                    ip = ip.strip()
                    parsed_local_blacklist.append(ip)
            
            print("Completed the local blacklist parsing.")

        except:
            print(f"ERR-IN04: Failed to open {self.blacklist_source}.")
    
        return parsed_local_blacklist


    def blacklist_check (self, ip_list):

        if self.blacklist_source != None:
            blacklist = self.local_blacklist()
        else:
            blacklist = self.osint_blacklist()

        for ip in ip_list:
            extracted_ip = ip['IP Address']

            if extracted_ip in blacklist:
                ip['Blacklisted'] = True
            else:
                ip['Blacklisted'] = False

        return ip_list