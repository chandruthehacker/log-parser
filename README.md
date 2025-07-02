# 🧠 Log Parser - Universal Log Analysis & Detection Tool

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Security](https://img.shields.io/badge/Security-Log%20Analysis-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

> 🔍 A powerful CLI tool for parsing, detecting, and analyzing various system and web server log files with real-time alerts and multiple output formats.

---

![Log Parser Banner](https://chandruthehacker.github.io/portfolio-website-old/projects/all-projects/log-analysis/assets/images/log-parser.webp)

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

| Log Type    | File Example         | Detection Modules Included                       |
|-------------|----------------------|-------------------------------------------------|
| `authlog`   | `/var/log/auth.log`  | SSH brute-force, sudo misuse, cron job injection |
| `syslog`    | `/var/log/syslog`    | Service restarts, odd-hour login attempts        |
| `apache`    | `access.log`         | DoS, 403/404 scans, bot agents                   |
| `nginx`     | `access.log`         | Similar to Apache support                      |

---

## ⚙️ Features

- 🔍 **Auto log type detection**
- 📊 **Multiple output formats**: CSV (`output/parsed_data.csv`, `output/alerts.csv`), Excel (`output/parsed_data.xlsx`, `output/alerts.xlsx`), JSON (`output/parsed_data.json`, `output/alerts.json`), CLI (terminal output), and Matplotlib charts (`output/visualization.png`)
- ⚡ **Real-time alerts** for suspicious activity displayed in the chosen output
- 📂 **Modular architecture** – easy to add new log types
- 🧠 **Built-in threat detection logic** per log type
- 🎯 **Clean, CLI-based interface** with loading spinners and banners

---

## 📦 Installation

### Prerequisites

- **Python 3.10 or higher** must be installed on your system.
- **pip** (Python package installer) should be installed. It usually comes with Python.
- **git** (for cloning the repository).

### Installation Steps for Linux (Recommended with Virtual Environment)

Using a virtual environment isolates the project dependencies and prevents conflicts with other Python projects on your system.

1.  **Install `venv` (if not already installed):**
    ```bash
    sudo apt update
    sudo apt install python3-venv
    ```

2.  **Clone the repository:**
    ```bash
    git clone https://github.com/chandruthehacker/log-parser.git
    cd log-parser
    ```

3.  **Create a virtual environment:**
    ```bash
    python3 -m venv venv
    ```

4.  **Activate the virtual environment:**
    ```bash
    source venv/bin/activate
    ```
    Your terminal prompt should now be prefixed with `(venv)`.

5.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

6.  **Run the parser (while the virtual environment is active):**
    ```bash
    python parser.py -f sample_log_files/sample_auth.log
    ```

7.  **To deactivate the virtual environment when you're finished:**
    ```bash
    deactivate
    ```

### Installation Steps for macOS (Recommended with Virtual Environment)

Using a virtual environment isolates the project dependencies and prevents conflicts with other Python projects on your system.

1.  **Ensure Python 3 and pip are installed.** macOS usually comes with Python, but you might need to install a newer version or `pip`. You can use Homebrew:
    ```bash
    brew install python3
    ```
    `pip` should be installed automatically with Python 3.

2.  **Install `venv` (if needed):**
    ```bash
    python3 -m pip install --upgrade pip  # Ensure pip is up-to-date
    python3 -m pip install virtualenv
    ```

3.  **Clone the repository:**
    ```bash
    git clone https://github.com/chandruthehacker/log-parser.git
    cd log-parser
    ```

4.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

5.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

6.  **Run the parser (while the virtual environment is active):**
    ```bash
    python parser.py -f sample_log_files/sample_auth.log
    ```

7.  **Deactivate the virtual environment:**
    ```bash
    deactivate
    ```

### Installation Steps for Windows

1.  **Install Python 3:** Download the latest version of Python 3 from the official Python website ([https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/)). Make sure to check the "Add Python to PATH" option during installation.

2.  **Open Command Prompt (cmd) or PowerShell.**

3.  **Upgrade pip (if needed):**
    ```bash
    python -m pip install --upgrade pip
    ```

4.  **Clone the repository:**
    ```bash
    git clone https://github.com/chandruthehacker/log-parser.git)
    cd log-parser
    ```

5.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

6.  **Run the parser:**
    ```bash
    python parser.py -f sample_log_files\sample_auth.log
    ```

---

## 🧪 Usage

```bash
python parser.py -f <log_file_path> [-t <log_type>] [-o <output_format>]
```
---

## ⚡ Example

```bash
python parser.py -f sample_log_files/sample_auth.log -t authlog -o json
```
---
**Then view the files in output/ folder
output/alerts.json
output/parsed_data.json**
---
