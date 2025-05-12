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
C:\Users\UncleSocks\Pixie\Pixie\src\pixie_unclesocks\Pixie>main.py -h

usage: main.py [-h] [-w WORDLIST] [-n] [-b BLACKLIST] [-o OUTPUT] [-f FILTER [FILTER ...]] [-a API]

Defender's 'Mini' IP Abuse and Blacklist Mass Lookup Tool.

options:
  -h, --help            show this help message and exit
  -w WORDLIST, --wordlist WORDLIST
                        Specify the location of the text file containing the IP addresses to be processed.
  -n, --netstat         Uses 'netstat -n' to capture public IP addresses communicating with the host.
  -b BLACKLIST, --blacklist BLACKLIST
                        [Optional] Specify the location of the text file containing the blacklist. If not specified Pixie will use StamparM's IpSum blacklist.
  -o OUTPUT, --output OUTPUT
                        [Optional] Specify the filename for the CSV file with the .csv extension.
  -f FILTER [FILTER ...], --filter FILTER [FILTER ...]
                        [Optional] Accepts the following filters: CONFIDENCE, TOTALREPORTS, DOMAIN, ISP, COUNTRY, and BLACKLISTED.
  -a API, --api API     [Optional] Enter the Abuse IP DB APIv2 key in-line.
```

### Filters
The tool is capable of accepting multiple filters by adding the `--filter` or `-f` option. It uses the Key-Operator-Value filter logic:

**Keys**:
- **CONFIDENCE** (int): Abuse IP DB confidence score. Accepts an integer as its value.
- **TOTALREPORTS** (int): Abuse IP DB total reports. Accepts an integer as its value.
- **ISP** (str): Abuse IP DB internet service provider (ISP). Accepts a string as its value.
- **COUNTRY** (str): Abuse IP DB country code. Accepts a string as its value.
- **DOMAIN** (str): Abuse IP DB domain. Accepts a string as its value.
- **BLACKLISTED** (bool): Whether the IP address is blacklisted. Accepts True (True/Yes/1) or False (False/No/0) as its value.

