import time
import json
import urllib.request
from enum import Enum

from requests import request




class URLs(Enum):
    ABUSEIPDB = 'https://api.abuseipdb.com/api/v2/check'
    BLACKLIST = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"


class AbuseIpDbLookup:
    
    def __init__(self, api_key):
        self.api_key = api_key

    def abuse_api_check(self):
        print("\nTesting Abuse IP DB API connection...")
        headers = {
            'Accept':'application/json',
            'Key':self.api_key
        }
        test_query = {'ipAddress':'8.8.8.8'}
        response = request(method='GET', url=URLs.ABUSEIPDB.value, headers=headers, params=test_query)
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

        headers = {
            'Accept':'application/json',
            'Key':self.api_key
        }

        for index, ip in enumerate(ip_list, start=1):
            query_string = {
                'ipAddress':ip,
                'maxAgeInDays':'30'
            }

            response = request(method='GET', url=URLs.ABUSEIPDB.value, headers=headers, params=query_string)
            decoded_response = json.loads(response.text)
            is_public = bool(decoded_response['data'].get('isPublic'))

            if is_public:

                ip_address = decoded_response['data'].get('ipAddress')
                country_code = decoded_response['data'].get('countryCode', "NONE")
                country_name = self.country_code_converter(country_code)
                usage_type = decoded_response['data'].get('usageType', "UNKNOWN")
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
                country_name = "PRIVATE"
                usage_type = "PRIVATE"
                hostnames = "NOT APPLICABLE"
                domain = "NOT APPLICABLE"
                isp = "NOT APPLICABLE"
                abuse_raw_score = 0
                abuse_score = 0
                total_reports = 0
                last_reported_at = "NOT APPLICABLE"

            processed_ip = {"IP Address":str(ip_address), "Country Code":str(country_code), "Country":str(country_name), \
                            "Usage Type":str(usage_type), "Hostnames":str(hostnames), "Domain":str(domain), "ISP":str(isp), \
                            "Raw Abuse Score":int(abuse_raw_score), "Abuse Score":str(abuse_score), \
                            "Total Reports":int(total_reports), "Last Reported At":str(last_reported_at)}
            processed_ip_list.append(processed_ip)
            print(f"\rProcessing {index}/{total_ips} IP addresses", end="", flush=True)

        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"\nLookup complete. Elapsed time: {elapsed_time:.2f} seconds.\n")

        return processed_ip_list
    
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
            country_name = "UNKNOWN"
        return country_name


class BlacklistLookup:

    def __init__(self, blacklist_source):
        self.blacklist_source = blacklist_source

    def osint_blacklist(self):
        print(f"Updating IP address blacklist from {URLs.BLACKLIST.value}")
        try:
            get_blacklist = urllib.request.urlopen(URLs.BLACKLIST.value).read().decode('utf-8')
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