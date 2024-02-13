import re
import subprocess
import urllib.request


def organization_parser(handler, organization_keyword, ip_list):

    print("Performing keyword parsing...")

    organization_keyword_list = organization_keyword.split(' ')
    output_list = []
    organization_keyword_counter = 0

    if organization_keyword_list[0] == "-":

        for ip in ip_list:
            ip_info = handler.getDetails(ip)

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

            ip_output = str(ip_info.ip + "[" + country + ":" + organization + ":" + hostname + "]")
            output_list.append(ip_output)
        
        organization_keyword_counter += 1

    elif organization_keyword_list[0] == "not":

        for keyword in organization_keyword_list[1:]:

            for ip in ip_list:
                ip_info = handler.getDetails(ip)

                try:
                    country = ip_info.country
                except:
                    country = "NONE"  

                try:
                    organization = ip_info.org.split(' ',1)[1].upper()
                    ip_organization = str(ip_info.org.lower())
                except:
                    organization = "NONE"
                    ip_organization = "NONE"

                try:
                    hostname = ip_info.hostname
                except:
                    hostname = "NONE"                    

                if keyword not in ip_organization:
                    ip_output = str(ip_info.ip + "[" + country + ":" + organization + ":" + hostname + "]")
                    output_list.append(ip_output)
            
            organization_keyword_counter += 1
    
    elif organization_keyword_list[0] != "not":

        for keyword in organization_keyword_list[0:]:

            for ip in ip_list:
                ip_info = handler.getDetails(ip)

                try:
                    country = ip_info.country
                except:
                    country = "NONE"

                try:
                    organization = ip_info.org.split(' ',1)[1].upper()
                    ip_organization = str(ip_info.org.lower())
                except:
                    organization = "NONE"
                    ip_organization = "NONE"  

                try:
                    hostname = ip_info.hostname
                except:
                    hostname = "NONE"

                if keyword in ip_organization:
                    ip_output = str(ip_info.ip + "[" + country + ":" + organization + ":" + hostname + "]")
                    output_list.append(ip_output)
            
            organization_keyword_counter += 1
    
    else:
        print("ERROR! Use the '-h' for information on how to use the tool.")

    output_dict = {'Keyword List': organization_keyword_list, 'Keyword Counter':organization_keyword_counter, 'Output List':output_list}
    return output_dict


def public_address_parser(ip_address):
    match = re.compile(r'((^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^::1$)|(^[fF][cCdD])/)|([a-zA-Z])').match(ip_address)
    if match:
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


def talos_blacklist():

    print("\nUpdating IP address blacklist... ")

    blacklist_url = "https://www.talosintelligence.com/documents/ip-blacklist"

    try:
        get_blacklist = urllib.request.urlopen(blacklist_url).read().decode('utf-8')
        parsed_blacklist = get_blacklist.strip().split("\n")
        print("IP address blacklist updated.")
    except:
        parsed_blacklist = []
        print("Error-003: Failed to update blacklist IP")

    return parsed_blacklist