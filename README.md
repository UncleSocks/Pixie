![image](https://github.com/user-attachments/assets/8c4a767e-a73b-4e51-b682-987fe7c7aaee)

# Pixie: Defender's "Mini" IP Abuse and Blacklist Mass Lookup Tool


An open-source script, named after my Mini Pinscher, that performs mass IP address lookups against AbuseIPDB and a local or OSINT (StamparM's Ipsum) blacklist.

Pixie either uses the specified local IP address list file or captures the foreign addresses from Netstat as its input. The tool leverages AbuseIPDB's APIv2 to perform address abuse lookups, then compares it to a local or StamparM's Ipsum OSINT blacklist to enhance their threat insight.

Users can also filter based on the confidence score, total number of reports, ISP, country code, domain name, and whether the IP is blacklisted.

![pixie](https://github.com/user-attachments/assets/0a4c7518-51e9-41b1-94ba-9f1a80a3f5b9)

## Prerequisites

Run `pip install -r requirements.txt` to install the tool's dependencies.

### Dependencies

Only two third-party libraries are required: `requests` to connect to the AbuseIPDB and `PrettyTable` to display the console output in tabular format.

## Usage
Typical usage syntax of the tool is to specify the IP list text file and optionally specify your filter(s):
```
main.py --wordlist <ip_list.txt> --filter <filter-one> <filter-n>
```

### Blacklist Threat Intelligence Feed
Pixie uses StamparM's Ipsum as the blacklist threat intelligence feed, which is updated daily: 
```
https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/ipsum.txt
```
However, users can also specify a local blacklist file using the `--blacklist <blacklist_location.txt>` option. This is especially useful for internal threat feeds.

### Netstat
When using the `--netstat` instead of `--wordlist` option, the tool captures and parses the foreign addresses from the output of the `netstat -n` command. This just-in-time approach collects all foreign addresses, regardless of their state, in order to acquire as much data as possible.

### Additional Options
You can append `-h` or `--help` to display a quick guide on how to use Pixie. This will display additional available options.
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
main.py --filter "CONFIDENCE >= 90" "BLACKLISTED == True" "ISP !contains Microsoft"
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

## Output
The output is displayed in the CLI and can be exported as a CSV file if the `--output` option was included. All CSV files will be stored under the `reports` subdirectory, which will be automatically created if it does not exist.


## Lite Versions
Multiple lightweight versions of Pixie are available in the `Lite` directory. These are single Python files that are non-interactive and _only_ execute bulk address lookups. They do not perform blacklist checks nor filtering.

For the Lite versions, the API key needs to be stored in the `api.txt` file.
