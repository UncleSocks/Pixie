import csv
from pathlib import Path
from enum import Enum

from prettytable import PrettyTable



class DisplayFields(Enum):
    FIELDNAMES = ['IP Address', 'Country Code', 'Country', 'Usage Type', 
                  'Hostnames', 'Domain', 'ISP', 'Abuse Score', 'Total Reports', 
                  'Last Reported At', 'Blacklisted']


class DisplayOutput:

    def __init__(self, filtered_ip_list):
        self.filtered_ip_list = filtered_ip_list

    def display_cli_table(self):
        table = PrettyTable()
        table.field_names = DisplayFields.FIELDNAMES.value
        for ip in self.filtered_ip_list:
            table.add_row([ip['IP Address'], ip['Country Code'], ip['Country'], ip['Usage Type'], ip['Hostnames'], ip['Domain'], 
                           ip['ISP'], ip['Abuse Score'], ip['Total Reports'], ip['Last Reported At'], ip['Blacklisted']])

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
                writer = csv.DictWriter(csv_export, fieldnames=DisplayFields.FIELDNAMES.value)
                writer.writeheader()
                for ip in self.filtered_ip_list:
                    writer.writerow({key: ip.get(key, '') for key in DisplayFields.FIELDNAMES.value})
            print("Successful exported the output.")
        except:
            raise ValueError(f"ERR-OUT01: Failed to export output to a CSV file.")   
        return