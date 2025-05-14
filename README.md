![image](https://github.com/UncleSocks/pixie-defenders-automated-ip-address-workflow/assets/79778613/054144a3-2155-438b-a775-6dadd00802dd)

# Pixie: Defender's "Mini" IP Abuse and Blacklist Mass Lookup Tool


An open-source script that performs mass IP address lookups against AbuseIPDB and a local or OSINT (StamparM's IpSum) blacklist.

Pixie either uses the specified local IP address list file or captures the foreign addresses the host machine is communicating with `netstat -n` as its input. The tool leverages AbuseIPDB's APIv2 to perform address abuse lookups, then compares it to a locally provided or StamparM's IpSum OSINT blacklist to enhance the threat insight of each IP address. 

Filters are also available, wherein users can filter based on AbuseIPDB's _confidence score_, _total reports_, _domain_, _ISP_, _country code_, and whether the IP is _blacklisted_. Output is displayed as a PrettyTable in the CLI, and it can be exported as a CSV file.

## Prerequisites

Run `pip install -r requirements.txt` to install the tool's dependencies.

### Dependencies

Only two third-party libraries are required: `requests` to connect to the AbuseIPDB and `PrettyTable` to display the console output in tabular format.

## Options

You can append `-h` or `--help` to display a quick guide on how to use Pixie, including the available options.
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
  -a API, --api API     [Optional] Enter the AbuseIPDB APIv2 key in-line.
```

## Filters
The tool is capable of accepting multiple filters by adding the `--filter` or `-f` option, which are applied after the tool has completed the AbuseIPDB and blacklist check for all IP addresses. 

```
C:\Users\UncleSocks\Pixie\Pixie\src\pixie_unclesocks\Pixie>main.py --filter "CONFIDENCE >= 90" "BLACKLISTED == True" "ISP !contains Microsoft"
```

### Filter Syntax Table

Pixie uses the `Key-Operator-Value` format for its filter syntax. The table below outlines the accepted keys, their definition, and their supported operators. Examples are also provided for reference.

| Key | Operators | Value Cast | Definition | Example |
| ---------- | -------------------- | --- | ----------------------------------------| ------------------ |
| CONFIDENCE | >=, <=, ==, !=, >, < | int | Filters IPs based on their confidence score in AbuseIPDB. | "CONFIDENCE >= 80" |
| TOTALREPORTS | >=, <=, ==, !=, >, < | int | Filters IPs by the number of abuse reported. |"TOTALREPORTS > 200" |
| ISP | contains, !contains | str | Filters IPs based on whether the internet service provider (ISP) contains (or does not contain) a keyword. | "ISP !contains Microsoft" |
| COUNTRYCODE | contains, !contains | str | IFilters IPs by whether their country code matches (or does not match) the input. | "COUNTRY contains PH" |
| DOMAIN | contains, !contains | str | Filters IPs by whether their domain name contains (or does not contain) a keyword. | "DOMAIN contains google" |
| BLACKLISTED | == | bool | Filters IPs based on whether they are on the blacklist (`True`, `Yes`, `1`) or not (`False`, `No`, `0`) | "BLACKLISTED == True" |

