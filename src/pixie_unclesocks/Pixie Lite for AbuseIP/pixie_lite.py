import re
import time
import requests
import json
import csv
import keyboard


class AbuseIpDbApiCheck:

    def __init__(self, abuse_api_file='api.txt'):

        self.abuse_api_file = abuse_api_file

    
    def abuse_api_file_check(self):
        with open(self.abuse_api_file) as abuse_api:
            abuse_api_key = abuse_api.read().strip()

            if not abuse_api_key:
                print("Abuse IP DB API key is not present.")
                return False
            
            else:
                return self.abuse_api_connect_check(abuse_api_key)
            

    def abuse_api_connect_check(self, abuse_api_key):

        print("Checking API key connection to Abuse IP DB...")

        url = 'https://api.abuseipdb.com/api/v2/check'
        connection_check_query = {'ipAddress':'8.8.8.8'}
        headers = {
            'Accept': 'application/json',
            'Key': abuse_api_key
        }

        response = requests.request(method="GET", url=url, headers=headers, params=connection_check_query)

        if response.status_code == 200:
            print("Abuse IP DB connection check complete.")
            return abuse_api_key
        else:
            print(f"Failed to connect to Abuse IP DB. Check your API key.")
            print(f"Status Code: {response.status_code}, Error: {response.text}")
            return False


class PixieAbuseIPDB():
    
    def __init__(self, ip_wordlist_file='ip.txt'):
        
        self.ip_wordlist_file = ip_wordlist_file
        self.ip_list = self.wordlist_process()


    def public_address_parser(self, ip_address):
        private_match = re.compile(r'((^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^::1$)|(^[fF][cCdD])/)|([a-zA-Z])').match(ip_address)
        return private_match
    

    def wordlist_process(self):
        print("Processing IP wordlist...")
        
        ip_list = []
        with open(self.ip_wordlist_file) as ip_wordlist:
            for ip in ip_wordlist:
                ip = ip.strip()
                ip_list.append(ip)

        return ip_list
    

    def abuse_ip_lookup(self, api_key):
        print("Performing AbuseIPDB lookup...")

        processed_ip_list = []
        raw_processed_ip_list = []
        total_ips = len(self.ip_list)
        start_time = time.time()
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept':'application/json',
            'Key': api_key
        }

        for index, ip in enumerate(self.ip_list, start=1):

            querystring = {
                'ipAddress':ip,
                'maxAgeInDays':'30'
            }

            if not self.public_address_parser(ip):

                response = requests.request(method='GET', url=url, headers=headers, params=querystring)
                decodedResponse = json.loads(response.text)

                ipAddress = decodedResponse['data']['ipAddress']

                try:
                    country_code = decodedResponse['data']['countryCode']
                    country_name = self.country_code_converter(country_code)
                except:
                    country_code = "NONE"
                    country_name = "NONE"

                hostnames = ", ".join(decodedResponse['data']['hostnames'])
                if not hostnames: 
                    hostnames = "NONE"

                try:
                    domain = decodedResponse['data']['domain']
                except:
                    domain = "NONE"

                try:
                    isp = decodedResponse['data']['isp']
                except:
                    isp = "NONE"

                abuseScoreRaw = decodedResponse['data']['abuseConfidenceScore']
                abuseScore = str(abuseScoreRaw) + "%"
                totalReports = decodedResponse['data']['totalReports']
                last_reported_at = decodedResponse['data']['lastReportedAt']

            else:
                ipAddress = ip
                country_code = "PRIVATE"
                country_name = "PRIVATE"
                hostnames = "NOT APPLICABLE"
                domain = "NOT APPLICABLE"
                abuseScore = "NOT APPLICABLE"
                totalReports = "NOT APPLICABLE"
                isp = "NOT APPLICABLE"
                last_reported_at = "NOT APPLICABLE"

            processed_ip = [str(ipAddress), str(country_code), str(country_name), str(hostnames), str(domain), str(abuseScore), str(totalReports), str(isp), str(last_reported_at)]
            processed_ip_list.append(processed_ip)

            raw_processed_ip = f"{ipAddress}[{country_name}:{isp}:{hostnames}:{domain}]"
            raw_processed_ip_list.append(raw_processed_ip)

            print(f"\rProcessing {index}/{total_ips} IP addresses", end="", flush=True)

        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"\nLookup complete. Elapsed time: {elapsed_time:.2f} seconds.\n")

        return self.output(raw_processed_ip_list, processed_ip_list)
    
    
    def output(self, raw_processed_ip_list, processed_ip_list):
        with open(f'./output.csv', 'w', newline='') as csv_export:
            csv_writer = csv.writer(csv_export)
            csv_writer.writerow(['IP ADDRESS', 'COUNTRY CODE', 'COUNTRY NAME', 'HOSTNAME', 'DOMAIN','ABUSE SCORE', 'TOTAL REPORTS', 'ISP', 'LAST REPORTED AT'])
            csv_writer.writerows(processed_ip_list)

        print("IP ADDRESS[COUNTRY:ISP:HOSTNAME:DOMAIN]\n")
        for raw_ip in raw_processed_ip_list:
            print(raw_ip)
        
        print("\nSuccessfully exported to a CSV file.")
        return

    @staticmethod
    def country_code_converter(country_code):
        #ISO 3166 Alpha 2
        country_dict = {
            #A
            "AF":"Afghanistan",
            "AX":"Åland Islands",
            "AL":"Albania",
            "DZ":"Algeria",
            "AS":"American Samoa",
            "AD":"Andorra",
            "AO":"Angola",
            "AI":"Anguilla",
            "AQ":"Antarctica",
            "AG":"Antigua and Barbuda",
            "AR":"Argentina",
            "AM":"Armenia",
            "AW":"Aruba",
            "AU":"Australia",
            "AT":"Austria",
            "AZ":"Azerbaijan",
            #B
            "BS":"Bahamas",
            "BH":"Bahrain",
            "BD":"Bangladesh",
            "BB":"Barbados",
            "BY":"Belarus",
            "BE":"Belgium",
            "BZ":"Belize",
            "BJ":"Benin",
            "BM":"Bermuda",
            "BT":"Bhutan",
            "BO":"Bolivia",
            "BA":"Bosnia and Herzegovina",
            "BW":"Botswana",
            "BR":"Brazil",
            "VI":"British Virgin Islands",
            "BN":"Brunei Darussalam",
            "BG":"Bulgaria",
            "BF":"Burkina Faso",
            "BI":"Burundi",
            #C
            "KH":"Cambodia",
            "CM":"Cameroon",
            "CA":"Canada",
            "CV":"Cape Verde",
            "KY":"Cayman Islands",
            "CF":"Central African Republic",
            "TD":"Chad",
            "CL":"Chile",
            "CN":"China",
            "CX":"Christmas Island",
            "CC":"Cocos (Keeling) Islands",
            "CO":"Colombia",
            "KM":"Comoros",
            "CD":"Congo Dem. Rep of the",
            "CG":"Congo, Republic of",
            "CK":"Cook Islands",
            "CR":"Costa Rica",
            "CI":"Cote D'Ivoire",
            "HR":"Croatia/Hrvatska",
            "CU":"Cuba",
            "CY":"Cyprus",
            "CZ":"Czech Republic",
            #D
            "DK":"Denmark",
            "DJ":"Djibouti",
            "DM":"Dominica",
            "DO":"Dominican Republic",
            #E
            "EC":"Ecuador",
            "EG":"Egypt",
            "SV":"El Salvador",
            "GQ":"Equatorial Guinea",
            "ER":"Eritrea",
            "EE":"Estonia",
            "ET":"Ethiopia",
            #F
            "FK":"Falkland Islands (Malvinas)",
            "FO":"Faroe Islands",
            "FJ":"Fiji",
            "FI":"Finland",
            "FR":"France",
            "GF":"French Guiana",
            "PF":"French Polynesia",
            "TF":"French Southern Territories",
            #G
            "GA":"Gabon",
            "GM":"Gambia",
            "GE":"Georgia",
            "DE":"Germany",
            "GH":"Ghana",
            "GI":"Gibraltar",
            "GR":"Greece",
            "GL":"Greenland",
            "GD":"Grenada",
            "GP":"Guadeloupe",
            "GU":"Guam",
            "GT":"Guatemala",
            "GN":"Guinea",
            "GW":"Guinea-Bissau",
            "GY":"Guyana",
            #H
            "HT":"Haiti",
            "VA":"Holy See (Vatican)",
            "HN":"Honduras",
            "HK":"Hong Kong",
            "HU":"Hungary",
            #I
            "IS":"Iceland",
            "IN":"India",
            "ID":"Indonesia",
            "IR":"Iran (Islamic Republic of)",
            "IQ":"Iraq",
            "IE":"Ireland",
            "IL":"Israel",
            "IT":"Italy",
            #J
            "JM":"Jamaica",
            "JP":"Japan",
            "JO":"Jordan",
            #K
            "KZ":"Kazakhstan",
            "KE":"Kenya",
            "KI":"Kiribati",
            "KP":"Korea, DPR",
            "KR":"Korea, Republic of",
            "KW":"Kuwait",
            "KG":"Kyrgyzstan",
            #L
            "LA":"Lao, PDR",
            "LV":"Latvia",
            "LB":"Lebanon",
            "LS":"Lesotho",
            "LR":"Liberia",
            "LY":"Libya",
            "LI":"Liechtenstein",
            "LT":"Lithuania",
            "LU":"Luxembourg",
            #M
            "MO":"Macau",
            "MK":"Macedonia",
            "MG":"Madagascar",
            "MW":"Malawi",
            "MY":"Malaysia",
            "MV":"Maldives",
            "ML":"Mali",
            "MT":"Malta",
            "MH":"Marshall Islands",
            "MQ":"Martinique",
            "MR":"Mauritania",
            "MU":"Mauritius",
            "YT":"Mayotte",
            "MX":"Mexico",
            "FM":"Micronesia, Fed. States of",
            "MD":"Moldova, Republic of",
            "MC":"Monaco",
            "MN":"Mongolia",
            "ME":"Montenegro",
            "MS":"Montserrat",
            "MA":"Morocco",
            "MZ":"Mozambique",
            "MM":"Myanmar",
            #N
            "NA":"Namibia",
            "NR":"Nauru",
            "NP":"Nepal",
            "NL":"Netherlands",
            "AN":"Netherlands Antilles",
            "NC":"New Caledonia",
            "NZ":"New Zealand",
            "NI":"Nicaragua",
            "NE":"Niger",
            "NG":"Nigeria",
            "NU":"Niue",
            "NF":"Norfolk Island",
            "MP":"Northern Mariana Islands",
            "NO":"Norway",
            #O
            "OM":"Oman",
            #P
            "PK":"Pakistan",
            "PW":"Palau",
            "PS":"Palestinian territories",
            "PA":"Panama",
            "PG":"Papua New Guinea",
            "PY":"Paraguay",
            "PE":"Peru",
            "PH":"Philippines",
            "PN":"Pitcairn Island",
            "PL":"Poland",
            "PT":"Portugal",
            "PR":"Puerto Rico",
            #Q
            "QA":"Qatar",
            #R
            "RE":"Réunion",
            "RO":"Romania",
            "RU":"Russian Federation",
            "RW":"Rwanda",
            #S
            "SH":"Saint Helena",
            "KN":"Saint Kitts and Nevis",
            "LC":"Saint Lucia",
            "PM":"Saint Pierre and Miquelon",
            "VC":"Saint Vincent and the Grenadines",
            "WS":"Samoa",
            "SM":"San Marino",
            "ST":"Sao Tome and Principe",
            "SA":"Saudi Arabia",
            "SN":"Senegal",
            "RS":"Serbia",
            "SC":"Seychelles",
            "SL":"Sierra Leone",
            "SG":"Singapore",
            "SK":"Slovakia (Slovak Rep.)",
            "SI":"Slovenia",
            "SB":"Solomon Islands",
            "SO":"Somalia",
            "ZA":"South Africa",
            "GS":"South Georgia and South Sandwich Islands",
            "SS":"South Sudan",
            "ES":"Spain",
            "LK":"Sri Lanka",
            "SD":"Sudan",
            "SR":"Suriname",
            "SJ":"Svalbard and Jan Mayen",
            "SZ":"Swaziland",
            "SE":"Sweden",
            "CH":"Switzerland",
            "SY":"Syrian Arab Republic",
            #T
            "TW":"Taiwan, Republic of China",
            "TJ":"Tajikistan",
            "TZ":"Tanzania",
            "TH":"Thailand",
            "TL":"Timor-Leste (East Timor)",
            "TG":"Togo",
            "TK":"Tokelau",
            "TO":"Tonga",
            "TT":"Trinidad and Tobago",
            "TN":"Tunisia",
            "TR":"Turkey",
            "TM":"Turkmenistan",
            "TC":"Turks and Caicos Islands",
            "TV":"Tuvalu",
            #U
            "UG":"Uganda",
            "UA":"Ukraine",
            "AE":"United Arab Emirates",
            "GB":"United Kingdom",
            "US":"United States",
            "UY":"Uruguay",
            "UZ":"Uzbekistan",
            #V
            "VU":"Vanuatu",
            "VA":"Vatican City State",
            "VE":"Venezuela",
            "VN":"Vietnam",
            "VG":"Virgin Islands (British)",
            "VI":"Virgin Islands (U.S.)",
            #W
            "WF":"Wallis and Futuna Islands",
            "EH":"Western Sahara",
            #YZ
            "YE":"Yemen",
            "ZM":"Zambia",
            "ZW":"Zimbabwe"
        }

        if country_code in country_dict:
            country_name = country_dict[country_code]
        else:
            country_name = "Country Code Not Found"
        return country_name
    
def completed_pause():
    print("Press enter or the space bar to continue...")
    wait = True
    while wait:
        if keyboard.read_key() == 'space' or keyboard.read_key() == 'enter':
            wait = False
            break


def banner():
    banner = """
    ____  _      _      
    |  _ \(_)_  _(_) ___ 
    | |_) | \ \/ / |/ _ \\
    |  __/| |>  <| |  __/
    |_|   |_/_/\_\_|\___|lite
    AbuseIPDB Reputation

    """

    return print(banner)
    

if __name__ == "__main__":
    banner()
    
    api_key = AbuseIpDbApiCheck().abuse_api_file_check()

    if api_key:
        PixieAbuseIPDB().abuse_ip_lookup(api_key)
        print("\nDone")
        completed_pause()
