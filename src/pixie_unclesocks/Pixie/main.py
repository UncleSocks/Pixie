from argparse import ArgumentParser
from getpass import getpass

from pixie.parsers import ip_parser, netstat_parser
from pixie.filters import FilterLogic
from pixie.lookups import AbuseIpDbLookup, BlacklistLookup
from pixie.display import DisplayOutput


def arguments():

    argument_parser = ArgumentParser(description="Defender's mini IP address workflow. Enter the organization keyword/s for searching, use space as a separator for multiple keywords; prepend the 'NOT' keyword to negate the search. The '-' character will process all IP addresses in the list without any keyword.")
    
    argument_parser.add_argument("-w","--wordlist", default="ip.txt", 
                                 help="Specify the location of the text file containing the IP addresses to be processed.")
    argument_parser.add_argument("-n", "--netstat", action="store_true", 
                                 help="Uses 'netstat -n' to capture public IP addresses communicating with the host.")
    argument_parser.add_argument("-b", "--blacklist", default=None, 
                                 help="[Optional] Specify the location of the text file containing the blacklist. If not specified Pixie will use the Cisco Talos Intelligence blacklist.")
    argument_parser.add_argument("-o", "--output", 
                                 help="[Optional] Specify the filename for the CSV file with the .csv extension.")
    argument_parser.add_argument("-f", "--filter", nargs="+", default=[], 
                                 help="[Optional] Accepts the following filters: CONFIDENCE, TOTALREPORTS, ISP, COUNTRY, and BLACKLISTED.")
    argument_parser.add_argument("-a", "--api")
    
    argument = argument_parser.parse_args()

    return argument


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
    

def main():

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


if __name__ == "__main__":
    main()

