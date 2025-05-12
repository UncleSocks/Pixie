import time
import requests
import json
import csv

class PixieLiteDomain:

    def __init__(self, api_key_file="api.txt", domain_list_file="domain.txt"):

        self.api_key_file = api_key_file
        self.api_key = self.api_key_process()

        self.domain_list_file = domain_list_file
        self.domain_list = self.domain_list_process()


    def api_key_process(self):
        with open(self.api_key_file) as api:
            api_key = api.read().strip()

        return api_key
    

    def domain_list_process(self):
        domain_list = []
        with open(self.domain_list_file) as domain_wordlist:
            for domain in domain_wordlist:
                domain = domain.strip()
                domain_list.append(domain)

        return domain_list

    
    def virustotal_domain_lookup(self):

        process_domain_list = []
        total_domains = len(self.domain_list)
        start_time = time.time()

        header = {
            "accept": "application/json",
            "x-apikey": f"{self.api_key}"
        }

        for index, domain in enumerate(self.domain_list, start=1):

            url = f"https://virustotal.com/api/v3/domains/{domain}"
            
            try:
                response = requests.get(url, headers=header)
            except requests.exceptions.RequestException as error:
                print(f"Request Error: {error}")
            
            decoded_response = json.loads(response.text)

            try:
                registrar = decoded_response['data']['attributes']['registrar']
            except:
                registrar = "NONE"
                
            malicious_count = decoded_response['data']['attributes']['last_analysis_stats']['malicious']
            suspicious_count = decoded_response['data']['attributes']['last_analysis_stats']['suspicious']
            undetected_count = decoded_response['data']['attributes']['last_analysis_stats']['undetected']
            harmless_count = decoded_response['data']['attributes']['last_analysis_stats']['harmless']

            total_count = malicious_count + suspicious_count + undetected_count + harmless_count

            print(f"Domain name: {domain}, Registrar: {registrar}, Total: {total_count}, Malicious: {malicious_count}, Suspicious: {suspicious_count}, Undetected: {undetected_count}, Harmless: {harmless_count}")

if __name__ == "__main__":
    PixieLiteDomain().virustotal_domain_lookup()
