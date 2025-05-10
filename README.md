# 🧠 Log Parser - Universal Log Analysis & Detection Tool

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Security](https://img.shields.io/badge/Security-Log%20Analysis-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

> 🔍 A powerful CLI tool for parsing, detecting, and analyzing various system and web server log files with real-time alerts and multiple output formats.

---

## 🚀 Overview

**Log Parser** is a universal log analysis tool built for cybersecurity professionals, SOC analysts, and sysadmins. It automatically detects the log type, parses each entry, and performs threat detection including:

- Brute-force login attempts
- Unauthorized/Forbidden access
- Suspicious user agents
- DoS activity detection
- Cron job injection & more (depending on log type)

---

## 🛠️ Supported Log Formats

| Log Type   | File Example        | Detection Modules Included |
|------------|---------------------|-----------------------------|
| `authlog`  | `/var/log/auth.log` | SSH brute-force, sudo misuse, cron injection |
| `syslog`   | `/var/log/syslog`   | Service restarts, odd-hour login attempts |
| `apache`   | `access.log`        | DoS, 403/404 scans, bot agents |
| `nginx`    | `access.log`        | Similar to Apache support   |

---

## ⚙️ Features

- 🔍 **Auto log type detection**
- 📊 **Multiple output formats**: CSV, Excel, JSON, CLI, and Matplotlib charts
- ⚡ **Real-time alerts** for suspicious activity
- 📂 **Modular architecture** – easy to add new log types
- 🧠 **Built-in threat detection logic** per log type
- 🎯 **Clean, CLI-based interface** with loading spinners and banners

---

## 📦 Installation

```bash
git clone https://github.com/chandruthehacker/log-parser.git
cd log-parser
pip install -r requirements.txt

---

## 🧪 Usage

```bash
python parser.py -f <log_file_path> [-t <log_type>] [-o <output_format>]

---

## Example

```bash
python parser.py -f sample_log_files/sample_auth.log -t authlog -o json
---
Then view the files in ## output/ folder
---
