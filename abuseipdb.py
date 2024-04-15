import os
import requests
import time
import argparse
import configparser
import pandas as pd
import csv
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich import print


def banner():
    console = Console(style="bold")
    console.print("\n")
    console.print("[red]           _                    _____ _____  _____  ____     _____ _               _                   [/red]")
    console.print("[red]     /\   | |                  |_   _|  __ \|  __ \|  _ \   / ____| |             | |  __              [/red]")
    console.print("[red]    /  \  | |__  _   _ ___  ___  | | | |__) | |  | | |_) | | |    | |__   ___  ___| | / /__ __ __      [/red]")
    console.print("[red]   / /\ \ | '_ \| | | / __|/ _ \ | | |  ___/| |  | |  _ <  | |    | '_ \ / _ \/ __| |/ / _ \ '__|      [/red]")
    console.print("[red]  / ____ \| |_) | |_| \__ \  __/_| |_| |    | |__| | |_) | | |____| | | |  __/ (__|   \  __/ |         [/red]")
    console.print("[red] /_/    \_\_.__/ \__,_|___/\___|_____|_|    |_____/|____/   \_____|_| |_|\___|\___|_|\_\___|_|         [/red]")
    console.print("\n")

parser = argparse.ArgumentParser(description=banner(), add_help=False)
parser.add_argument('-help', dest='help',action="store_true", help='Print this help message')
parser.add_argument('-ip', dest='ip', metavar='IP', help='Check an individual IP address.')
parser.add_argument('-file', dest='ips_file', metavar='FILE', help='Check a list of IP addresses from a file (one per line)"')
parser.add_argument('-subnet', dest='subnet', metavar='SUBNET', help='Subnet Check')
parser.add_argument('-output', dest='output_file', metavar='FILE', help='Write list of malicious IPs with score greater than or equal to Confidence Score')
parser.add_argument('-details', dest='details', action="store_true", help='Print details of IP check. (Score, Domain, Reports, Country, Lastest Report)')
parser.add_argument('-config', dest='config', action="store_true", help='Open config menu. (edit API_KEY or Confidence Score)')
args = parser.parse_args()


def print_help():
    print("""
    Python Script for AbuseIPDB's API.
    
    Usage:
    python abuseipdb.py <option> [<value> ...]
    
    Options:
    
    -i | -ip           : Check an individual IP address.
    -s | -subnet       : Check an individual Subnet. (/24 to /32)
    -f | -file         : Check a list of IP addresses from a file (one per line)
    -c | -config       : Open settings menu. (edit defalts settings)
    -o | -output       : Choose where to save malicious IP
    -d | -details      : Print details of IP check. (Score, Domain, Reports, Country, Lastest Report)
    -h | -help         : Print this help information.
    

    Examples:

    python abuseipdb.py -ip 1.2.3.4 -d
    python abuseipdb.py -subnet 1.2.3.4/24 
    python abuseipdb.py -file /path/to/file.txt
    python abuseipdb.py -config
    \n""")



config_file = 'config.ini'
config = configparser.ConfigParser()



# CHECK


def check_ip(ip,details):
    config.read(config_file)
    API_KEY = config['DEFAULT']['API_KEY']

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    table = Table(title="List of Checked IP")
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        r_Score = data['data']['abuseConfidenceScore']
        r_Domain = data['data']['domain']
        r_Reports_Count = data['data']['totalReports']
        r_Country_Code = data['data']['countryCode']
        r_Lastest_Report = data['data']['lastReportedAt']
        
        
        table = Table(title="List of Checked IP")
        table.add_column("IP Address", justify="left")
        table.add_column("Score", justify="center")
        table.add_column("Domain", justify="left")
        table.add_column("Reports", justify="center")
        table.add_column("Country", justify="center")
        table.add_column("Lastest Report", justify="left")

        console = Console()
        config.read(config_file)
        settings_confidenceScore = config['DEFAULT']['confidenceScore']
        settings_showDetails = config['DEFAULT']['showDetails']
        if args.ip:
            if details == True or settings_showDetails == "yes" or settings_showDetails == "Yes" or settings_showDetails == "y" or settings_showDetails == "Y" or args.details == True:
                if data['data']['abuseConfidenceScore'] >= int(settings_confidenceScore):
                    table.add_row(ip, str(r_Score), r_Domain, str(r_Reports_Count), r_Country_Code, r_Lastest_Report)
                    console.print(table)
                else: 
                    print(f"\nIP address [bold yellow]{ip}[/bold yellow] assigned to domain [bold yellow]{r_Domain}[/bold yellow] has not been reported as malicious with a confidence score of [[bold yellow]{data['data']['abuseConfidenceScore']}[/bold yellow]].\n")
            else:
                if data['data']['abuseConfidenceScore'] >= int(settings_confidenceScore):
                    print(f"\nIP address [bold yellow]{ip}[/bold yellow] has been reported as malicious with a confidence score of [[bold red]{data['data']['abuseConfidenceScore']}[/bold red]].\n")
                else:
                    print(f"\nIP address [bold yellow]{ip}[/bold yellow] has not been reported as malicious with a confidence score of [[bold yellow]{data['data']['abuseConfidenceScore']}[/bold yellow]].\n")              
        return (ip, str(r_Score), r_Domain, str(r_Reports_Count), r_Country_Code, r_Lastest_Report)
    else:
        errors = response.json().get('errors', [])
        error_detail = errors[0].get('detail', 'Errore sconosciuto')
        print(f'\nError checking IP Address [bold yellow]{ip}[/bold yellow]: [red]{error_detail}[/red]\n')


#optional details
def check_ips_from_file(filename, output_file, details):
    console = Console()
    table = Table(title=f"List of Checked IP from [yellow]{filename}[/yellow]")
    table.add_column("IP Address", justify="left")
    table.add_column("Score", justify="center")
    table.add_column("Domain", justify="left")
    table.add_column("Reports", justify="center")
    table.add_column("Country", justify="center")
    table.add_column("Lastest Report", justify="left")
    config.read(config_file)
    settings_confidenceScore = config['DEFAULT']['confidenceScore']
    malicious_ips = []
    try:
        with open(filename, 'r') as f:
            ips = f.readlines()
            progress = Progress(transient=True)
            task = progress.add_task(f"\nProcessing IPs from [yellow]{filename}[/yellow]", total=len(ips))
            with progress:
                for ip in ips:
                    ip = ip.strip()
                    result = check_ip(ip, details)
                    
                    progress.update(task, advance=1)
                    if result:
                        table.add_row(*result)
                    if int(result[1]) >= int(settings_confidenceScore):
                        result = (*result, f"https://abuseipdb.com/check/{ip}")
                        malicious_ips.append(result)
                progress.stop()
            console.print(table)
    except FileNotFoundError:
        print(f"\nFile [yellow]{filename}[/yellow] not found.\n")
    
    if output_file:
        if output_file.endswith(".csv"):
            with open(output_file, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["IP", "Score","Domain","Reports","Country","Lastest Report","Link to AbuseIPDB"])
                for row in malicious_ips:
                    writer.writerow(row)
            print(f"\nList of malicious IPs with score greater than or equal to [bold red]{settings_confidenceScore}[/bold red] has been written to [yellow]{output_file}[/yellow].\n")
            print(f"\nYou can modify the confidence score in the config file [yellow]{config_file}[/yellow] or with command [yellow]-config.[/yellow]\n")
        elif output_file.endswith(".xlsx") or output_file.endswith(".xls") or output_file.endswith(""):
            if output_file.endswith(""):
                output_file = f"{output_file}.xlsx"
            try:
                df = pd.DataFrame(malicious_ips, columns=["IP", "Score","Domain","Reports","Country","Lastest Report","Link to AbuseIPDB"])
                df.to_excel(output_file, index=False)
            except FutureWarning: 
                print("Use xlsx for better results.")
                pass
            print(f"\nList of malicious IPs with score greater than or equal to [bold yellow]{settings_confidenceScore}[/bold yellow] has been written to [yellow]{output_file}[/yellow].\n")
    else:
        print("\nNo output file specified.\n")

def check_subnet(subnet, output_file):
    config.read(config_file)
    API_KEY = config['DEFAULT']['API_KEY']
    settings_confidenceScore = int(config['DEFAULT']['confidenceScore'])
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
        }
    response = requests.get(f'https://api.abuseipdb.com/api/v2/check-block?network={subnet}', headers=headers)

    if response.status_code == 200:
        data = response.json()
        for record in data['data']['reportedAddress']: 
            r_Score = record['abuseConfidenceScore']
            r_Score += r_Score
            r_Score = r_Score / len(data['data']['reportedAddress'])
            avg_r_Score = round(r_Score, 2)

        table = Table(title=f"List of Checked Subnet's IP ([yellow]{subnet}[/yellow])")
        table.add_column("IP Address", justify="left")
        table.add_column("Score", justify="center")
        table.add_column("Reports", justify="center")
        table.add_column("Country", justify="center")
        table.add_column("Lastest Report", justify="left")
        for record in data['data']['reportedAddress']:
            ip = record['ipAddress']
            score = record['abuseConfidenceScore']
            reports = record['numReports']
            country = record['countryCode']
            lastest_report = record['mostRecentReport']
            table.add_row(ip, str(score), str(reports), country, lastest_report)
        console = Console()
        console.print(table)

        print(f'This subnet [bold yellow]{subnet}[/bold yellow] has a reputation score average of [bold yellow]{avg_r_Score}[/bold yellow]\n')
    else:   
        errors = response.json().get('errors', [])
        error_detail = errors[0].get('detail', 'Errore sconosciuto')
        print(f'\nError checking IP Address [bold yellow]{ip}[/bold yellow]: [red]{error_detail}[/red]\n')
    if output_file:
        output_list = []
        for record in data['data']['reportedAddress']:
            ip = record['ipAddress']
            score = record['abuseConfidenceScore']
            reports = record['numReports']
            country = record['countryCode']
            lastest_report = record['mostRecentReport']
            output_list.append([ip, score, reports, country, lastest_report, f"https://abuseipdb.com/check/{ip}"])
        if output_file.endswith(".csv"):
            with open(output_file, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["IP", "Score","Reports","Country Code","Last Report","Link to AbuseIPDB"])
                writer.writerow(output_list)
            print(f"\nList of IPs in subnet [bold yellow]{subnet}[/bold yellow] has been written to [yellow]{output_file}[/yellow].\n")
        elif output_file.endswith(".xlsx") or output_file.endswith(".xls"):
            try:
                df = pd.DataFrame(output_list, columns=["IP", "Score","Reports","Country Code","Last Report","Link"])
                df.to_excel(output_file, index=False) 
            except FutureWarning: 
                print("Use xlsx for better results.")
                pass
            print(f"\nList of IPs in subnet [bold yellow]{subnet}[/bold yellow] has been written to [yellow]{output_file}[/yellow].\n")
        else:
            print("\nInvalid output file format.\n")
    else:
        print("\nNo output file specified.\n")

#END CHECK

config_file = 'config.ini'
config = configparser.ConfigParser()

def config_menu():
    try:
        if not os.path.exists(config_file):
            print("Config file not found. Creating a new one.")
            config['DEFAULT'] = {
                'confidenceScore': '50',
                'showDetails': 'False'
            }
            with open(config_file, 'w') as f:
                config.write(f)

        config.read(config_file)
        api_key = config['DEFAULT']['API_KEY']
        while True:
            print("")
            print('AbuseIPDB Checker Configuration:')
            print('1. Edit API Key            Current: ' + config['DEFAULT']['API_KEY'])
            print('2. Edit Confidence Score   Current: ' + config['DEFAULT']['confidenceScore'])
            print('3. Edit Show Details       Current: ' + config['DEFAULT']['showDetails'])
            print('4. Exit')
            choice = input('\nEnter your choice: ')

            if choice == '1':
                api_key = input('\nEnter your AbuseIPDB API key: ')
                config['DEFAULT']['API_KEY'] = api_key
                with open(config_file, 'w') as f:
                    config.write(f)
            elif choice == '2':
                settings_confidenceScore = input('\nEnter the value for Confidence Score: ')
                config['DEFAULT']['confidenceScore'] = settings_confidenceScore
                with open(config_file, 'w') as f:
                    config.write(f)
            elif choice == '3':
                settings_showDetails = input('\nDo you want to see IP details by default? (y/n): ')
                if settings_showDetails == 'y' or settings_showDetails == 'Y' or settings_showDetails == 'yes' or settings_showDetails == 'Yes' or settings_showDetails == 'YES':
                    config['DEFAULT']['showDetails'] = True
                with open(config_file, 'w') as f:
                    config.write(f)
            elif choice == '4':
                print_help()
                break
            else:
                print('Invalid choice. Please try again.')
    except:
        print("\n\nExit\n")
        time.sleep(1)   
        print_help()


def setup_api():
    try:
        print("Please enter your AbuseIPDB API key.")
        print("Chek out https://www.abuseipdb.com/account/api to get your API key.")
        print("")
        API_KEY = input("Enter your API key here: ")
        config['DEFAULT']['API_KEY'] = API_KEY
        with open(config_file, 'w') as f:
            config.write(f)   
        print("Saved.")
        time.sleep(1)
        os.system('cls')
        banner()
        print_help()
        return API_KEY
    except:
        print("\n\nExit\n")

def main():
    if not os.path.exists(config_file):
        config['DEFAULT'] = {
            'confidenceScore': '50',
            'showDetails': 'False',
            'API_KEY': setup_api()
        }
        with open(config_file, 'w') as f:
            config.write(f)
 
    
    
#Check if API key is empty
    config.read(config_file)

    if not config.has_option('DEFAULT', 'API_KEY'):
        print("API Key is empty. Please enter your API key.")
        setup_api()
    elif args.help:
        print_help()
    elif args.ip:
        check_ip(args.ip, args.details)
    elif args.subnet:
        check_subnet(args.subnet, args.output_file)
    elif args.ips_file:
        check_ips_from_file(args.ips_file, args.output_file, args.details)
    elif args.config:
        config_menu()
    else:
        print("\nPlease use -h or --help for show all commands\n")

if __name__ == "__main__":
    main()
