
![Logo](https://i.imgur.com/HEgWwcF.png)
# AbuseIPDB Checker Tool

This is a Python script that uses the AbuseIPDB API to check whether an IP address has been reported as malicious. The user can enter an IP address, a subnet or a list of IP addresses in a file, and the script will check each one and provide a report on its reputation score. The script reads configuration options from a config file and requires the user to input their API key.

## AbuseIPDB API KEY

To use this tool, you will need to have the official API KEY from https://www.abuseipdb.com/account/api

## Installation

Install AbuseIPDB Checker with git

```bash
 git clone https://github.com/ndscplnt/AbuseIPDB-Checker.git
 cd AbuseIPDB-Checker
```

You have to install the requirements before use this tool

```bash
 pip install -r requirements.txt
```

Run the tool with command:

```bash
 python abuseipdb.py
```
## Usage/Examples

```bash
python abuseipdb.py -help

python abuseipdb.py -ip 123.456.789.0 -d

python abuseipdb.py -file path/to/file.txt -o output.xlsx 

```

## Thanks to
- [AbuseIPDB](https://www.abuseipdb.com)
- [Termcolor](https://github.com/termcolor/termcolor)
- [Rich](https://github.com/Textualize/rich)
- [Pandas](https://github.com/pandas-dev/pandas)

## License
MIT © [ndscplnt](https://github.com/ndscplnt/AbuseIPDB-Checker/blob/main/LICENSE.md)
