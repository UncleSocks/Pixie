![image](https://github.com/UncleSocks/pixie-defenders-automated-ip-address-workflow/assets/79778613/054144a3-2155-438b-a775-6dadd00802dd)

# Pixie: Defender's "Mini" IP Abuse and Blacklist Mass Lookup Tool


An open-source script that performs mass IP address lookups against Abuse IP DB and a local or OSINT (StamparM's IpSum) blacklist.

Pixie either uses the specified local IP address list file or captures the foreign addresses the host machine is communicating with `netstat -n` as its input. The tool leverages Abuse IP DB's APIv2 to perform address abuse lookups, then compares it to a locally provided or StamparM's IpSum OSINT blacklist to enhance the threat insight of each IP address. 

Filters are also available, wherein users can filter based on Abuse IP DB's _confidence score_, _total reports_, _domain_, _ISP_, _country code_, and whether the IP is _blacklisted_. Output is displayed as a PrettyTable in the CLI, and it can be exported as a CSV file.

## Prerequisites

Run `pip install -r requirements.txt` to install the tool's dependencies.

### Dependencies

Only two third-party libraries are required: `requests` to connect to the Abuse IP DB and `PrettyTable` to display the console output in tabular format.

## Options

You can use the `-h` or `--help` option to display a quick guide on how to use Pixie.
```
C:\Users\Pixie>pixie.py -h
usage: pixie.py [-h] [-w WORDLIST] [-n] [-i IOC] [-o OUTPUT] [-s SOURCE]

Defender's mini IP address workflow. Enter the organization keyword/s for searching, use space as a separator for multiple keywords; prepend the 'NOT' keyword to negate the search. The '-' character will process all IP addresses in the
list without any keyword.

options:
  -h, --help            show this help message and exit
  -w WORDLIST, --wordlist WORDLIST
                        Specify the location of the text file containing the IP addresses to be processed.
  -n, --netstat         Uses 'netstat -n' to capture public IP addresses communicating with the host.
  -i IOC, --ioc IOC     [Optional] Specify the location of the text file containing the blacklist. If not specified Pixie will use the Cisco Talos Intelligence blacklist.
  -o OUTPUT, --output OUTPUT
                        [Optional] Specify the filename for the CSV file with the .csv extension.
  -s SOURCE, --source SOURCE
                        Specify IP address lookup OSINT source (currently supports IPInfo and IBM X-Force)
```

### Available Options

`-s` or `--source`: Specify which source Pixie will use to look up the IP addresses. Currently, it supports IPInfo and IBM X-Force. When unspecified it will query to IPInfo by default.

`-w` or `--wordlist`: Specify the location of the text file containing the list of IP addresses to be processed. A `sample_list.txt` file is provided for reference.

`-n` or `--netstat`: Uses the `netstat -n` command to capture and parse the remote IP addresses communicating with the host machine. 

`-i` or `--ioc`: Specify the location of the text file containing the set of blacklisted IP addresses. If this option is not specified, Pixie defaults to using the Cisco Talos Intelligence blacklist.

`-o` or `--output`: Specify the CSV filename with the '.csv' extension.


**Note:** Either the `-w` or `-n` must be specified but not both. The inclusion of none or both will result in an error.

## Usage

**Wordlist Option Usage:** Run the `pixie.py -w <location_of_wordlist.txt>` command on the host machine.

**Netstat Option Usage:** Run the `pixie.py -n` command to use Netstat as the wordlist.

**Wordlist Option with Blacklist File:** Run the `pixie.py -w <location_of_wordlist.txt> -i <location_of_blacklist.txt>` command if you want to use your own set of blacklisted IP addresses.

**Wordlist Option with Blacklist File and CSV File Output:** Run the `pixie.py -w <location_of_wordlist.txt> -o <output_filename.csv>` command if you have a wordlist and want to export the output in a CSV file.

**Use IBM X-Force as IP Address Look-Up Source:** Run the `pixie.py -s x -w <location_of_wordlist.txt>` command if you want to use IBM X-Force API to lookup the IP addresses in the specified wordlist.

**Example:** `pixie.py -w C:\Users\$Username\Documents\List_of_IP_Addresses.txt`

```
C:\Users\Pixie>pixie.py -w sample_list.txt

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
    .+       .+;+; .X$&&&Xx:      +$&&&$x:X&&&$x. X$&&&$$x;+$&&&$+.  ;X&&$x;         
    :;        :;:;.                                                                  
    ;:            ;;       Defender's IP Mini Automated Address Workflow                                         
   .;:            .::         

    In loving memory of my dog, Pixie.


Created by Tyrone Kevin Ilisan (@unclesocks)
2024.4.0

[+] Automatically queries the IP addresses in the wordlist on IPInfo and IBM X-Force
[+] Accepts organization keywords for filtering.
[+] Outputs the results in IPADDRESS[COUNTRY:ORG:HOSTNAME] format.
[+] Exports to an CSV file (optional).
[+] Checks if any of the IP addresses are present in the blacklist:
    https[://]www[.]talosintelligence[.]com/documents/ip-blacklist

Note: The tool requires the IPInfo token to connect to IPInfo.


Github: https[://]github[.]com/UncleSocks/pixie-automated-defenders-ip-address-workflow
   
=============================================================================================

Enter token: ***************
```

The script will ask for your IPInfo access token or IBM X-Force API key and password and your desired IP address organization keyword/s for searching when running the command. 

**NOTE:** When pasting, use the right-click button of your mouse.

### Organization Keyword Search

Use a space to separate multiple keywords (e.g., AMAZON MICROSOFT). The script will look up each IP address in your text file list or netstat on IPInfo or IBM X-Force. It will only output the addresses that match ANY of the provided organization keywords. In short, the script will show you the list of addresses belonging to the organization/s in your search.

```
Enter organization keyword (e.g., Microsoft): AMAZON MICROSOFT
Processing wordlist.
Performing keyword parsing...
```

### Negating Organization Keyword Search

If you want to negate your search, prepend a `NOT` keyword on your search (e.g., NOT AMAZON MICROSOFT GOOGLE). Similarly, the script will still look up each IP address inside the list or netstat but will only output the IP address that does not belong to the organization/s in your search.
```
Enter organization keyword (e.g., Microsoft): NOT AMAZON MICROSOFT
Processing wordlist...
Performing keyword parsing...
```

### Lookup All IP Addresses In The Wordlist
If you want to look up all IP addresses in your list, use the `-` key.
```
Enter organization keyword (e.g., Microsoft): -
Processing wordlist.
Performing keyword parsing...
```

### Blacklist Check
Pixie now features an automated blacklist check against the Cisco Talos Intelligence IP Blacklist:
```
https://www.talosintelligence.com/documents/ip-blacklist
```
The IP blacklist is updated every time you run Pixie. Suppose an IP address in your wordlist or netstat matches an address in the blacklist. In that case, it will be displayed in the **BLACKLISTED IPs** section in the output.

You can use the `-i` option to run the processed IP addresses against your own blacklist file. A **sample_blacklist.txt** file is included in the repository for reference.


## Output

Pixie displays the CLI or CSV file output when the `-o` option is specified.

The script displays a two-section output: the parsed addressed then the matched blacklisted IP addresses.
```
=============================================================================================
                                          OUTPUT
=============================================================================================

37.187.59.174[FR:OVH SAS:174.ip-37-187-59.eu]
95.160.47.124[PL:VECTRA S.A.:095160047124.rzeszow.vectranet.pl]
150.162.157.117[BR:UNIVERSIDADE FEDERAL DE SANTA CATARINA:cca157-117.cca.ufsc.br]
217.36.254.7[GB:BRITISH TELECOMMUNICATIONS PLC:host217-36-254-7.in-addr.btopenworld.com]
110.121.97.125[CN:CHINA TIETONG TELECOMMUNICATIONS CORPORATION:NONE]
78.165.166.162[TR:TTNET A.S.:78.165.166.162.dynamic.ttnet.com.tr]
104.218.195.108[US:FRONTIER COMMUNICATIONS OF AMERICA, INC.:NONE]
68.195.205.216[US:CABLEVISION SYSTEMS CORP.:ool-44c3cdd8.static.optonline.net]
52.68.0.1[JP:AMAZON.COM, INC.:ec2-52-68-0-1.ap-northeast-1.compute.amazonaws.com]
52.68.1.90[JP:AMAZON.COM, INC.:ec2-52-68-1-90.ap-northeast-1.compute.amazonaws.com]
13.107.6.153[US:MICROSOFT CORPORATION:NONE]
204.79.197.215[US:MICROSOFT CORPORATION:NONE]
147.161.132.5[NL:ZSCALER SWITZERLAND GMBH:NONE]
136.226.170.4[DE:ZSCALER, INC.:NONE]

=============================================================================================
                                     BLACKLISTED IPs
=============================================================================================


Updating IP address blacklist...
IP address blacklist updated.

131.253.18.12[US:NONE:NONE]
131.253.18.11[US:NONE:NONE]
46.149.184.5[UA:KALUSKA INFORMATSIYNA MEREZHA LLC:tun-46-149-184-5.kim.in.ua]
46.211.241.39[UA:"KYIVSTAR" PJSC:46-211-241-39.mobile.kyivstar.net]
109.196.187.208[UA:TELERADIOCOMPANY "CABLE TELEVISION MEREZHI PLUS" LTD:pppoe-187-208.alexandriya.net]
178.159.36.185[RU:PRIVATE INTERNET HOSTING LTD:NONE]
59.99.43.205[IN:NATIONAL INTERNET BACKBONE:NONE]
163.172.154.105[FR:SCALEWAY S.A.S.:105-154-172-163.instances.scw.cloud]
```

### CSV Output

CSV file outputs are saved under the `./reports/` folder. An `output.csv` sample file is provided for reference.

Similar to the CLI output, the CSV file is divided into two sections: the processed IP address list and the blacklisted IP addresses.

![image](https://github.com/UncleSocks/pixie-defenders-automated-ip-address-workflow/assets/79778613/6f319e3a-3145-4cc1-9bb6-77c9f7ae3f20)


