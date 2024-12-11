
![Logo](https://i.imgur.com/HEgWwcF.png)
# AbuseIPDB Checker Tool

This Python script leverages the AbuseIPDB API to determine whether an IP address has been flagged as malicious. Users can input a single IP address, a subnet, or a list of IP addresses from a file, and the script will perform reputation checks for each entry, providing a detailed report on its reputation score. The script is configurable, allowing users to customize settings via a configuration file.

<p align="center">
    <img src="https://i.imgur.com/vo5EuCP.png" />
</p>
<p align="center">
    <i>It is capable of functioning both via command-line and graphical interface.</i>
</p>

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

Run the tool via GUI:
```bash
 python abuseipdb.py -gui
```

Run the tool via command line:
```bash
 python abuseipdb.py
```

## Usage/Examples

```bash
python abuseipdb.py -help

python abuseipdb.py -gui

python abuseipdb.py -ip 123.456.789.0 -d

python abuseipdb.py -file path/to/file.txt -o output.xlsx 

```

## Thanks to
- [AbuseIPDB](https://www.abuseipdb.com)
- [pyQt6](https://doc.qt.io/qtforpython-6/)
- [Termcolor](https://github.com/termcolor/termcolor)
- [Rich](https://github.com/Textualize/rich)
- [Pandas](https://github.com/pandas-dev/pandas)

## License
MIT © [ndscplnt](https://github.com/ndscplnt/AbuseIPDB-Checker/blob/main/LICENSE)
