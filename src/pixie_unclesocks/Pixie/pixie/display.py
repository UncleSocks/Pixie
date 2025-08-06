import csv
from pathlib import Path

from prettytable import PrettyTable



class DisplayOutput:

    def __init__(self, filtered_ip_list):

        self.filtered_ip_list = filtered_ip_list

    def display_cli_table(self):
        table = PrettyTable()
        table.field_names = ['IP Address', 'Country Code', 'Hostnames', 'Domain', 'ISP', 
                             'Abuse Score', 'Total Reports', 'Last Reported At', 'Blacklisted']

        for ip in self.filtered_ip_list:
            table.add_row([ip['IP Address'], ip['Country Code'], ip['Hostnames'], ip['Domain'], 
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
                field_names = ['IP Address', 'Country Code', 'Hostnames', 'Domain', 'ISP', 
                               'Abuse Score', 'Total Reports', 'Last Reported At', 'Blacklisted']
                writer = csv.DictWriter(csv_export, fieldnames=field_names)
                writer.writeheader()

                for ip in self.filtered_ip_list:
                    writer.writerow({key: ip.get(key, '') for key in field_names})

            print("Successful exported the output.")

        except:
            raise ValueError(f"ERR-OUT01: Failed to export output to a CSV file.")   
        return