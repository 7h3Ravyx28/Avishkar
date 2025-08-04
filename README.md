# 🛡 Avishkar - Mini Threat Hunting Tool

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-Threat%20Hunting-orange.svg)]()

Avishkar is a **lightweight log analysis tool** built for junior security analysts and researchers to detect suspicious SSH login activity.  
It parses logs, detects failed login attempts, checks for suspicious IPs, and generates detailed reports.  

---

##  Features

- 📑 **Parse SSH Authentication Logs** – Extract login attempts from `auth.log`
- 🚨 **Failed Login Detection** – Highlight IPs with excessive failed attempts
- 🌎 **GeoIP Lookup** – Check IP country (using `GeoLite2-City.mmdb`)
- 📊 **Severity Classification** – Flag suspicious IPs by threshold
- 🔄 **Real-time Monitoring** – Watch logs live with `--watch`
- 📤 **Export Reports** – Export results to **CSV** or **JSON**
- 🖥 **CLI Friendly** – Fully command-line based
- ⚡ **Lightweight & Fast** – No heavy dependencies

---

## 🛠 Tech Stack

- **Language:** Python 3.9+
- **Libraries:**  
  ```bash
  pip install -r requirements.txt

 ### Run Basic Log Analysis
```bash
  python main.py --log logs/auth.log
```
### With GeoIP Lookup
```bash
python main.py --log logs/auth.log --geoip GeoLite2-City.mmdb
```
### Change Severity Threshold
```bash
python main.py --log logs/auth.log --threshold 3
```
### Export to CSV or JSON
```bash
python main.py --log logs/auth.log --export csv --output report.csv
python main.py --log logs/auth.log --export json --output report.json
```
### Real-Time Log Monitoring
```bash
python main.py --log logs/auth.log --watch
```

