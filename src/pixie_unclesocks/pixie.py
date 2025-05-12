import re
import operator
import time
import json
import subprocess
import csv
import urllib.request
from argparse import ArgumentParser
from pathlib import Path
from getpass import getpass

from requests import request
from prettytable import PrettyTable


def arguments():

    argument_parser = ArgumentParser(description="Defender's mini IP address workflow. Enter the organization keyword/s for searching, use space as a separator for multiple keywords; prepend the 'NOT' keyword to negate the search. The '-' character will process all IP addresses in the list without any keyword.")
    argument_parser.add_argument("-w","--wordlist", default="ip.txt", help="Specify the location of the text file containing the IP addresses to be processed.")
    argument_parser.add_argument("-n", "--netstat", action="store_true", help="Uses 'netstat -n' to capture public IP addresses communicating with the host.")
    argument_parser.add_argument("-b", "--blacklist", default=None, help="[Optional] Specify the location of the text file containing the blacklist. If not specified Pixie will use the Cisco Talos Intelligence blacklist.")
    argument_parser.add_argument("-o", "--output", help="[Optional] Specify the filename for the CSV file with the .csv extension.")
    argument_parser.add_argument("-f", "--filter", nargs="+", default=[])
    argument_parser.add_argument("-a", "--api")
    argument = argument_parser.parse_args()

    return argument


def ip_parser(wordlist):

    print("Parsing IP address from the wordlist...")

    total_ips = len(wordlist)
    ip_list = []
    
    try:
        with open(wordlist) as ip_wordlist:
            for ip in ip_wordlist:
                ip = ip.strip()
                ip_list.append(ip)
    except:
        raise ValueError(f"ERR-IN01: File '{wordlist}' cannot be found. If the --wordlist option is not specified, Pixie uses the default 'ip.txt' file as its wordlist")
    
    print(f"Parsing complete. Captured {total_ips} IP addresses.\n")

    return ip_list


def netstat_parser():

    print("Processing Netstat output...")

    ns_output = subprocess.check_output('netstat -n').decode('ascii').strip().split("\n")
    ns_output_startline = ns_output[5:]

    ns_foreign_address_parser = [output[2] for output in map(str.split, ns_output_startline)]
    ns_address_list = []
    seen_foreign_addresses = set()

    for foreign_address in ns_foreign_address_parser:
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
        print(f"Done parsing IP addresses fromo Netstat. Captured {total_ips} IP addresses")
    
    return ns_address_list



def public_address_parser(ip_address):
    private_match = re.compile(r'((^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^::1$)|(^[fF][cCdD])/)|([a-zA-Z])').match(ip_address)
    return private_match



class AbuseIpDbLookup():
    
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

            if not public_address_parser(ip):

                response = request(method='GET', url=url, headers=headers, params=query_string)
                decoded_response = json.loads(response.text)

                ip_address = decoded_response['data']['ipAddress']

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
    


class BlacklistLookup():

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



class FilterLogic():

    def __init__(self, filter_args):

        self.filter_args = filter_args

        self.operator_map = {
            ">": operator.gt,
            ">=": operator.ge,
            "<": operator.lt,
            "<=": operator.le,
            "==": operator.eq,
            "=": operator.eq,
            "!=": operator.ne,
            "contains": self._contains,
            "!contains": self._not_contains
        }

        self.filter_config = {
            "CONFIDENCE": {
                "extract": lambda record: record.get('Raw Abuse Score', 0),
                "cast": int
            },

            "TOTALREPORTS": {
                "extract": lambda record: record.get('Total Reports', 0),
                "cast": int
            },

            "ISP": {
                "extract": lambda record: record.get('ISP', '').upper(),
                "cast": str
            },

            "COUNTRY": {
                "extract": lambda record: record.get('Country Code', '').upper(),
                "cast": str
            },

            "BLACKLISTED": {
                "extract": lambda record: record.get('Blacklisted', False),
                "cast": self._bool_cast
            }
        }
        

    def _contains(self, a_string, b_string):
        return b_string.upper() in a_string.upper()
    
    def _not_contains(self, a_string, b_string):
        return b_string.upper() not in a_string.upper()

    def _bool_cast(self, value):

        if value.strip().upper() in ("TRUE", "YES", "1"):
            return True
        elif value.strip().upper() in ("FALSE", "NO", "0"):
            return False
        else:
            raise ValueError(f"ERR-FL05: Invalid value {value} for BLACKLISTED field. Use True/False, Yes/No, or 1/0 only.")


    def build_filter(self):
        
        filter_pattern = re.compile(r'((((?P<filter_key_int>CONFIDENCE|TOTALREPORTS)(?:\s*)?(?P<filter_op_int>>=|<=|==|!=|>|<|=))|((?P<filter_key_str>ISP|COUNTRY)(?:\s*)?(?P<filter_op_str>contains|!contains))|((?P<filter_key_bl>BLACKLISTED)(?:\s*)?(?P<filter_op_bl>==|=)))(?:\s*)?(?P<filter_value>\S+))', 
                                    re.IGNORECASE)
        if not filter_pattern:
            raise ValueError(f"Invalid filter format {filter}")

        parsed_filters = []

        for filter in self.filter_args:
            filter_match = filter_pattern.fullmatch(filter)
            if not filter_match:
                raise ValueError(f"ERR-FL01: Invalid filter format: '{filter}'. Expected format like 'CONFIDENCE >= 85'.")            

            key = filter_match.group('filter_key_int') or filter_match.group('filter_key_str') or filter_match.group('filter_key_bl')
            op = filter_match.group('filter_op_int') or filter_match.group('filter_op_str') or filter_match.group('filter_op_bl')
            value = filter_match.group('filter_value')

            config = self.filter_config.get(key)
            if not config:
                raise ValueError(f"ERR-FL02: Unknown filter key {key}.")

            extracted = config['extract']
            cast = config['cast']

            try:
                op_func = self.operator_map[op]
            except:
                raise ValueError(f"ERR-FL03: Invalid operator. Use --help option for more information on the available operators.")

            try:
                value = cast(value)
            except:
               raise ValueError(f"ERR-FL04: Invalid cast for value {value}.") 

            parsed_filters.append(lambda record, op=op_func, value=value, extracted=extracted: op(extracted(record), value))

        return parsed_filters
    

    def apply_filter(self, ip_list, filters):

        if self.filter_args:
            applied_filters = filters
            filtered_ip_list = [ip for ip in ip_list if all(filter(ip) for filter in applied_filters)]

        else:
            filtered_ip_list = ip_list
        
        return filtered_ip_list
            


class DisplayOutput():

    def __init__(self, filtered_ip_list):

        self.filtered_ip_list = filtered_ip_list

    def display_cli_table(self):

        table = PrettyTable()
        table.field_names = ['IP Address', 'Country Code', 'Hostnames', 'Domain', 'ISP', 'Abuse Score', 'Total Reports', 'Last Reported At', 'Blacklisted']

        for ip in self.filtered_ip_list:
            table.add_row([ip['IP Address'], ip['Country Code'], ip['Hostnames'], ip['Domain'], ip['ISP'], ip['Abuse Score'], ip['Total Reports'], ip['Last Reported At'], ip['Blacklisted']])

        table.align = "l"
        table.max_width['Hostnames'] = 20
        table.max_width['Domain'] = 20
        table.max_width['ISP'] = 20

        return print(table)
    

    def report_dir_check(self):

        print("\nChecking for the required directory for CSV export...")
        report_dir = Path(".\\reports")

        if report_dir.exists() and report_dir.is_dir():
            print("The reports directory already exists, proceeding with the export.")
            return
        else:
            print("Creating the reports directory...")
            report_dir.mkdir(parents=True, exist_ok=True)
            print("Directory created.")
            return


    def csv_output(self, filename):

        print("Exporting output to a CSV file...")

        try:
            with open(f'./reports/{filename}', 'w', newline='') as csv_export:
                field_names = ['IP Address', 'Country Code', 'Hostnames', 'Domain', 'ISP', 'Abuse Score', 'Total Reports', 'Last Reported At', 'Blacklisted']
                writer = csv.DictWriter(csv_export, fieldnames=field_names)
                writer.writeheader()

                for ip in self.filtered_ip_list:
                    writer.writerow({key: ip.get(key, '') for key in field_names})

            print("Successful exported the output.")

        except:
            raise ValueError(f"ERR-OUT01: Failed to export output to a CSV file.")
        
        return
            



def pixie_logo():

    pixie_logo = """

=============================================================================================
=============================================================================================                                                                                
                     _____
               \/_  | Awo |    
              ..     -----                                                                
           +++xX:  /                                                                 
          ;;;+XX;                                      ^^                                
        ++++++++:                   ^^                                                
       :x++;++++.                                                 ^^                   
          ;++;;::                                 ^^                               
         .+++;:::              ^^                                                      
        .;;;;++;::                                                                   
       ;+;;;;::;;;:.   ;&&&&&&&&&&&&+ ;&&&&&; x&&&&&&&&+&&&&&&.:&&&&&:               
      :++;;;:::;++:;    :&&&&x  $&&&&::&$;     :&&&&&&.&&$     :&$;                  
      :+;;;;;+;;x+ +;.  X&&&&:  &&&&X:&&&&&:    ;&&&&&&$      :&&&&&:   X&&&&&&:     
      +++++xX++XX:  ;;:;&&&&$:$&&&&+.$&&&&+      +&&&&&X      $&&&&+ .$&&X  X&&$     
     :;X;;++XXXXx     :+;+&&&&&$X.  .$&&&$      +&&&&&&&;     $&&&$ ;&&&&&&&&&&+     
     ;+:   ;;+;++;    X&$+;+.       +&&&&:    x&&+.&&&&&&;   +&&&&: $&&&$            
    :+:     :;;xx+  :X&&&&$:      .X&&&&&:;+$&&&: :$&&&&&&;:x&&&&&: X&&&&&$&&X       
    .+       .+;+; .X$&&&Xx:      +$&&&$x:X&&&$x. X$&&&$$x;+$&&&$+.  ;X&&$x;   v2025.2.0      
    :;        :;:;.                                                                  
    ;:            ;;      Defender's Mini Automated IP Address Workflow                                         
   .;:            .::                   

    In loving memory of my dog, Pixie.

    
[+] Perform bulk IP address lookup on Abuse IP DB.
[+] Identify blacklisted IP addresses against a local or OSINT (Stamparm's IPSum) list.
[+] Filter output based on confidence score, total reports, hostnames, and more.
[+] Export the output to a CSV file.

=============================================================================================
    """

    return print(pixie_logo)
    



if __name__ == "__main__":

    pixie_logo()
    args = arguments()

    api_key = args.api if args.api else getpass("Enter Abuse IP DB API Key > ")

    if not args.netstat:
        ip_list = ip_parser(args.wordlist)
    else:
        ip_list = netstat_parser()

    filter = FilterLogic(args.filter)
    applied_filter = filter.build_filter()

    abuse = AbuseIpDbLookup(api_key)
    check_abuse_connection = abuse.abuse_api_check()

    processed_ip_list = AbuseIpDbLookup(api_key).abuse_lookup(ip_list)
    blacklisted_processed_ip_list = BlacklistLookup(args.blacklist).blacklist_check(processed_ip_list)

    filtered_ip = filter.apply_filter(blacklisted_processed_ip_list, applied_filter)

    display = DisplayOutput(filtered_ip).display_cli_table()
    if args.output:
        export_csv = DisplayOutput(filtered_ip)
        export_csv.report_dir_check()
        export_csv.csv_output(args.output)
