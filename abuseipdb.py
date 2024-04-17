import os
import subprocess
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
import gui as abgui


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

def report(output_file, malicious_ips):
    settings_confidenceScore = int(config['DEFAULT']['confidenceScore'])
    if output_file:
        if output_file.endswith(".csv"):
            with open(output_file, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["IP", "Score", "Domain", "Reports", "Country", "Lastest Report", "Link to AbuseIPDB"])
                for row in malicious_ips:
                    writer.writerow(row)
            print(f"\nList of malicious IPs with score greater than or equal to [bold red]{settings_confidenceScore}[/bold red] has been written to [yellow]{output_file}[/yellow].\n")
            print(f"\nYou can modify the confidence score in the config file [yellow]{config_file}[/yellow] or with command [yellow]-config.[/yellow]\n")
        elif output_file.endswith((".xlsx", ".xls", "")):
            if output_file.endswith(""):
                output_file = f"{output_file}.xlsx"
            try:
                df = pd.DataFrame(malicious_ips, columns=["IP", "Score", "Domain", "Reports", "Country", "Lastest Report", "Link to AbuseIPDB"])
                df.to_excel(output_file, index=False)
            except FutureWarning: 
                print("Use xlsx for better results.")
                pass
            print(f"\nList of malicious IPs with score greater than or equal to [bold yellow]{settings_confidenceScore}[/bold yellow] has been written to [yellow]{output_file}[/yellow].\n")
        else:
            print("\nNo output file specified.\n")

def check_ip(ip, details, gui=False, bulk=False):
    config.read(config_file)
    API_KEY = config['DEFAULT']['API_KEY']
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        r_Score = str(data['data']['abuseConfidenceScore'])
        r_Domain = data['data']['domain']
        r_Reports_Count = str(data['data']['totalReports'])
        r_Country_Code = data['data']['countryCode']
        r_Lastest_Report = data['data']['lastReportedAt']
        
        console = Console()
        table = Table(title="List of Checked IP", caption=f"Default confidence score:  [yellow]{config['DEFAULT']['confidenceScore']}[yellow]")
        table.add_column("IP Address", justify="left")
        table.add_column("Score", justify="center")
        table.add_column("Domain", justify="left")
        table.add_column("Reports", justify="center")
        table.add_column("Country", justify="center")
        table.add_column("Lastest Report", justify="left")
        
        settings_confidenceScore = int(config['DEFAULT']['confidenceScore'])
        settings_showDetails = bool(config['DEFAULT']['showDetails'])
        
        if gui:
            if details and bulk == False:
                gui_output = f"This IP has been reported as malicious!\n"
                gui_output += f"IP Address: {ip}\n"
                gui_output += f"Score: {r_Score}\n"
                gui_output += f"Domain: {r_Domain}\n"
                gui_output += f"Reports: {r_Reports_Count}\n"
                gui_output += f"Country: {r_Country_Code}\n"
                gui_output += f"Lastest Report: {r_Lastest_Report}\n"
                return gui_output
            else:            
                results = {
                    "ip": ip,
                    "r_Score": r_Score,
                    "r_Domain": r_Domain,
                    "r_Reports_Count": r_Reports_Count,
                    "r_Country_Code": r_Country_Code,
                    "r_Lastest_Report": r_Lastest_Report
                }
                return results
        else:
            if details:
                if int(r_Score) >= settings_confidenceScore and int(r_Score) >= 1:
                    if bulk == True:
                        return ip, r_Score, r_Domain, r_Reports_Count, r_Country_Code, r_Lastest_Report
                    table.add_row(ip, r_Score, r_Domain, r_Reports_Count, r_Country_Code, r_Lastest_Report)
                    console.print(table)
                    print("")
                else:
                    if bulk == True:
                        return ip, r_Score, r_Domain, r_Reports_Count, r_Country_Code, r_Lastest_Report
                    table.add_row(ip, r_Score, r_Domain, r_Reports_Count, r_Country_Code, r_Lastest_Report)
                    table.caption = f"IP address [bold green]{ip}[/bold green] has not been reported as malicious!\n"
                    console.print(table)
                    print("")
            else:
                if int(r_Score) >= settings_confidenceScore:
                    print(f"\nIP address [bold red]{ip}[/bold red] assigned to domain [bold red]{r_Domain}[/bold red] has been reported as malicious with a confidence score of [[bold red]{data['data']['abuseConfidenceScore']}[/bold red]].\n")
                else:
                    print(f"\nIP address [bold green]{ip}[/bold green] assigned to domain [bold green]{r_Domain}[/bold green] has not been reported as malicious with a confidence score of [[bold green]{data['data']['abuseConfidenceScore']}[/bold green]].\n")    
    else:
        errors = response.json().get('errors', [])
        error_detail = errors[0].get('detail', 'Unknown error')
        output_results = f'\nError checking IP {ip}: {error_detail}\n'
        print(f'\nError checking IP Address [bold yellow]{ip}[/bold yellow]: [red]{error_detail}[/red]\n')
        return output_results


def bulkcheck(ips, filename, output_file, gui=False):
    console = Console()
    table = Table(title=f"List of Checked IP from [yellow]{filename}[/yellow]")
    table.add_column("IP Address", justify="left")
    table.add_column("Score", justify="center")
    table.add_column("Domain", justify="left")
    table.add_column("Reports", justify="center")
    table.add_column("Country", justify="center")
    table.add_column("Latest Report", justify="left")
    
    config.read(config_file)
    settings_confidenceScore = int(config['DEFAULT']['confidenceScore'])
    malicious_ips = []
    
    if gui == False:
        try:
            with open(filename, 'r') as f:
                ips = f.readlines()
                progress = Progress(transient=True)
                task = progress.add_task(f"\nProcessing IPs from [yellow]{filename}[/yellow]", total=len(ips))
                with progress:
                    for ip in ips:
                        ip = ip.strip()
                        result = check_ip(ip, details=True, gui=False, bulk=True)
                        if result:
                            table.add_row(*result)
                        if int(result[1]) >= settings_confidenceScore and int(result[1]) >= 1:
                            result = (*result, f"https://abuseipdb.com/check/{ip}")
                            malicious_ips.append(result)
                        progress.update(task, advance=1)
                progress.stop()
            console.print(table)
            if output_file:
                if output_file.endswith(".csv"):
                    with open(output_file, mode='w', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow(["IP", "Score", "Domain", "Reports", "Country", "Latest Report", "Link to AbuseIPDB"])
                        for row in malicious_ips:
                            writer.writerow(row)
                    print(f"\nList of malicious IPs with score greater than or equal to [bold red]{settings_confidenceScore}[/bold red] has been written to [yellow]{output_file}[/yellow].\n")
                    print(f"\nYou can modify the confidence score in the config file [yellow]{config_file}[/yellow] or with command [yellow]-config.[/yellow]\n")
                else:
                    if not output_file.endswith(".xlsx"):
                        output_file += ".xlsx"
                    try:
                        df = pd.DataFrame(malicious_ips, columns=["IP", "Score", "Domain", "Reports", "Country", "Latest Report", "Link to AbuseIPDB"])
                        df.to_excel(output_file, index=False)
                    except FutureWarning: 
                        print("Use xlsx for better results.")
                        pass
                    print(f"\nList of malicious IPs with score greater than or equal to [bold yellow]{settings_confidenceScore}[/bold yellow] has been written to [yellow]{output_file}[/yellow].\n")
        except FileNotFoundError:
            print(f"\nIPs list file [yellow]{filename}[/yellow] not found.\n")
    else:
        results = []  
        if ips:
            ips = [ip.strip() for ip in ips.splitlines() if ip.strip()]
            for ip in ips:
                result = check_ip(ip, details=True, gui=True, bulk=True)
                if result:
                    table.add_row(*result)
                    r_Score = int(result['r_Score'])
                    results.append(result)
                    if r_Score >= 1:
                        malicious_ips.append(result)
            count_ip = len(ips)
            count_malicious_ip = len(malicious_ips)
            output_results = f'''Total IP checked: {count_ip}
    Reported IPs: {count_malicious_ip}
    Here is the list of malicious IPs:\n'''
            for row in malicious_ips:
                output_results += f"{row['ip']}\n"
            if output_file:
                if output_file.endswith(".csv"):
                    with open(output_file, mode='w', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow(["IP", "Score", "Domain", "Reports", "Country", "Latest Report", "Link to AbuseIPDB"])
                        for row in results:  
                            if int(row['r_Score']) >= settings_confidenceScore:
                                writer.writerow(row.values())
                    output_results += f"\nList of malicious IPs with score greater than or equal to {settings_confidenceScore} has been written to {output_file}\n"
                    output_results += f"You can modify the confidence score in the config file {config_file} or with command -config.\n"
                else:
                    if not output_file.endswith(".xlsx"):
                        output_file += ".xlsx"
                    try:
                        excelresults = []
                        for row in results:
                            if int(row['r_Score']) >= settings_confidenceScore:
                                excelresults.append([row['ip'], row['r_Score'], row['r_Domain'], row['r_Reports_Count'], row['r_Country_Code'], row['r_Lastest_Report'], f"https://abuseipdb.com/check/{row['ip']}"])
                        df = pd.DataFrame(excelresults, columns=["IP", "Score", "Domain", "Reports", "Country", "Latest Report", "Link to AbuseIPDB"])
                        df.to_excel(output_file, index=False)
                        output_results += f"\nList of malicious IPs with score greater than or equal to {settings_confidenceScore} has been written to {output_file}\n"
                        output_results += f"\nYou can modify the confidence score in the config file {config_file} or with command -config.\n"
                    except FutureWarning: 
                        print("Use xlsx for better results.")
                        pass
            else:
                output_results += "\nYou can generate a report file by using the output option.\n"
            return output_results
        
#Check Subnet
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
        results = [] 
        malicious_ips = [] 
        for record in data['data']['reportedAddress']: 
            results.append({
                "IP": record['ipAddress'],
                "Score": record['abuseConfidenceScore'],
                "Reports": record['numReports'],
                "Country": record['countryCode'],
                "Lastest Report": record['mostRecentReport'],
                "Link": f"https://abuseipdb.com/check/{record['ipAddress']}"
            })
            if record['abuseConfidenceScore'] >= settings_confidenceScore:
                malicious_ips.append(record['ipAddress'])

        scores = [record['abuseConfidenceScore'] for record in data['data']['reportedAddress']]
        avg_r_Score = round(sum(scores) / len(scores), 2) if scores else 0

        table = Table(title=f"List of Checked Subnet's IP ([yellow]{subnet}[/yellow])")
        table.add_column("IP Address", justify="left")
        table.add_column("Score", justify="center")
        table.add_column("Reports", justify="center")
        table.add_column("Country", justify="center")
        table.add_column("Latest Report", justify="left")
        for record in results:
            table.add_row(record['IP'], str(record['Score']), str(record['Reports']), record['Country'], record['Lastest Report'])
        console = Console()
        console.print(table)
        print(f'This subnet [bold yellow]{subnet}[/bold yellow] has a reputation score average of [bold yellow]{avg_r_Score}[/bold yellow]\n')

        output_results = f'''Total IP checked: {len(data['data']['reportedAddress'])}
Average Score: {avg_r_Score}
Here is the list of malicious IPs:\n'''
        for ip in malicious_ips:
            output_results += f"{ip}\n"
        if output_file:
            if output_file.endswith(".csv"):
                with open(output_file, mode='w', newline='') as file:
                    writer = csv.DictWriter(file, fieldnames=["IP", "Score", "Reports", "Country", "Lastest Report", "Link"])
                    writer.writeheader()
                    for record in results:
                        if record['Score'] >= settings_confidenceScore:
                            writer.writerow(record)
                print(f"\nList of IPs in subnet [bold yellow]{subnet}[/bold yellow] has been written to [yellow]{output_file}[/yellow].\n")
                output_results += f"\nList of IPs in subnet {subnet} has been written to {output_file}.\n"
            else:
                if not output_file.endswith(".xlsx"):
                    output_file += ".xlsx"
                try:
                    excelresults = []
                    for row in results:
                        if row['Score'] >= settings_confidenceScore:
                            excelresults.append([row['IP'], row['Score'], row['Reports'], row['Country'], row['Lastest Report'], f"https://abuseipdb.com/check/{row['IP']}"])
                    df = pd.DataFrame(excelresults, columns=["IP", "Score", "Reports", "Country", "Latest Report", "Link to AbuseIPDB"])
                    df.to_excel(output_file, index=False)
                    print(f"\nList of IPs in subnet [bold yellow]{subnet}[/bold yellow] has been written to [yellow]{output_file}[/yellow].\n")
                    output_results += f"\nList of IPs in subnet {subnet} has been written to {output_file}.\n"
                except FutureWarning: 
                    print("Use xlsx for better results.")
                    pass
    else:   
        errors = response.json().get('errors', [])
        error_detail = errors[0].get('detail', 'Unknown Error')
        output_results = f'\nError checking subnet {subnet}: {error_detail}\n'
        print(f'\nError checking subnet [bold yellow]{subnet}[/bold yellow]: [red]{error_detail}[/red]\n')
    return output_results


#END CHECKS
 
config_file = 'config.ini'
config = configparser.ConfigParser()

def config_menu():
    try:
        if not os.path.exists(config_file):
            print("Config file not found. Creating a new one.")
            config['DEFAULT'] = {
                'confidenceScore': '0',
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
                settings_confidenceScore = input('\nEnter the value for Confidence Score (Default: 0): ')
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
    elif args.gui:
        abgui.create_gui()
    elif args.ip:
        if args.details:
            details = True
            check_ip(args.ip, details)
        else:
            details = False
            check_ip(args.ip, details)
    elif args.subnet:
        check_subnet(args.subnet, args.output_file)
    elif args.ips_file:
        bulkcheck(args.ips_file, filename=args.ips_file, output_file=args.output_file, gui=False)
    elif args.config:
        config_menu()
    else:
        print("\nPlease use -h or --help for show all commands\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=banner(), add_help=False)
    parser.add_argument('-help', dest='help',action="store_true", help='Print this help message')
    parser.add_argument('-gui', dest='gui', action="store_true", help='Open GUI')
    parser.add_argument('-ip', dest='ip', metavar='IP', help='Check an individual IP address.')
    parser.add_argument('-file', dest='ips_file', metavar='FILE', help='Check a list of IP addresses from a file (one per line)"')
    parser.add_argument('-subnet', dest='subnet', metavar='SUBNET', help='Subnet Check')
    parser.add_argument('-output', dest='output_file', metavar='FILE', help='Write list of malicious IPs with score greater than or equal to Confidence Score')
    parser.add_argument('-details', dest='details', nargs="?", const='True', help='Print details of IP check. (Score, Domain, Reports, Country, Lastest Report)')
    parser.add_argument('-config', dest='config', action="store_true", help='Open config menu. (edit API_KEY or Confidence Score)')
    args = parser.parse_args()
    if not args.gui: 
        main()  
    else:
        subprocess.Popen(["pythonw", "-c", "from gui import create_gui; create_gui()"], shell=False)