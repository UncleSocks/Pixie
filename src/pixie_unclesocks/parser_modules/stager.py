import re
from collections import Counter
from parser_modules.parsers import osint_blacklist
from init import blacklist_wordlist


def staged_output(output_dict):
    output = output_dict
    output_list = []

    if output['Keyword Counter'] == 1:

        for entry in output['Output List']:
            #print(entry, end="\n")
            output_list.append(entry)

    elif output['Keyword Counter'] > 1 and output['Keyword List'][0] == "not": 
        output_counter = Counter(output['Output List'])
        output_duplicates = [item for item, count in output_counter.items() if count > (output['Keyword Counter'] - 1)]

        for duplicate in output_duplicates:
            output_list.append(duplicate)

    elif output['Keyword Counter'] > 1 and output['Keyword List'][0] != "not":
        output_uniques = set(output['Output List'])

        for unique in output_uniques:
            output_list.append(unique)

    else:
        print("Error-004: Invalid input. Use the '-h' for information on how to use the tool.")

    return output_list
    

def blacklist_check(output_list, blacklist_file):

    if blacklist_file == False:
        blacklist = osint_blacklist()
    else:
        blacklist = blacklist_wordlist()

    blacklisted_ips_list = []

    for entry in output_list:
        ip_address = entry.split("[")[0]

        if ip_address in blacklist:
            blacklisted_ips_list.append(entry)

    if not blacklisted_ips_list:
        return
    else:
        return blacklisted_ips_list
    

def export_parser(output_list, source):

    export_list = []

    for entry in output_list:
        ip_information_parser = re.search(r'\[(.*?)\]', entry).group(1).split(':')
        
        if source == "ibm_xforce":
            ip_address = entry.split("[")[0]
            country = ip_information_parser[0]
            organization = ip_information_parser[1]
            risk_rating = ip_information_parser[2]
            category = ip_information_parser[3]

            current_ip_info = [ip_address, country, organization, risk_rating, category]

        else:
        
            ip_address = entry.split("[")[0]
            country = ip_information_parser[0]
            organization = ip_information_parser[1]
            hostname = ip_information_parser[2]

            current_ip_info = [ip_address, country, organization, hostname]
        
        export_list.append(current_ip_info)

    return export_list


def export_blacklist_parser(blacklist_list, source):

    export_blacklist_list = []

    if blacklist_list:
    
        for entry in blacklist_list:
            ip_information_parser = re.search(r'\[(.*?)\]', entry).group(1).split(':')

            if source == "ibm_xforce":
                ip_address = entry.split("[")[0]
                country = ip_information_parser[0]
                organization = ip_information_parser[1]
                risk_rating = ip_information_parser[2]
                category = ip_information_parser[3]

                current_ip_info = [ip_address, country, organization, risk_rating, category]
                
            else: 
                ip_address = entry.split("[")[0]
                country = ip_information_parser[0]
                organization = ip_information_parser[1]
                hostname = ip_information_parser[2]

                current_ip_info = [ip_address, country, organization, hostname]

            export_blacklist_list.append(current_ip_info)

    return export_blacklist_list
