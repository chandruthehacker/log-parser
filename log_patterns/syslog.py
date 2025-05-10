import re
from datetime import datetime

LOG_PATTERN = re.compile(
    r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>[\w\/\-.]+)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<message>.*)$'
)

# Message-based patterns
SSH_PATTERN = re.compile(r'Accepted|Failed password for (?P<username>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)')
SU_PATTERN = re.compile(r'session opened for user (?P<username>\w+)')
CRON_PATTERN = re.compile(r'CMD \((?P<command>.+?)\)')
IP_PATTERN = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+)')

def parse_log(line):
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    data = match.groupdict()

    # Build timestamp
    try:
        current_year = datetime.now().year
        timestamp = datetime.strptime(
            f"{data['month']} {data['day']} {current_year} {data['time']}",
            "%b %d %Y %H:%M:%S"
        ).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        timestamp = f"{data['month']} {data['day']} {data['time']}"

    # Extract data from message
    message = data["message"]
    username = None
    source_ip = None
    event_type = data["process"].lower()
    command = None

    if event_type == "sshd":
        m = SSH_PATTERN.search(message)
        if m:
            username = m.group("username")
            source_ip = m.group("ip")
            event_type = "ssh"

    elif event_type == "su":
        m = SU_PATTERN.search(message)
        if m:
            username = m.group("username")
            event_type = "su"

    elif event_type == "cron":
        m = CRON_PATTERN.search(message)
        if m:
            command = m.group("command")
            event_type = "cron"

    # Fallback generic IP extraction
    if not source_ip:
        ip_match = IP_PATTERN.search(message)
        if ip_match:
            source_ip = ip_match.group("ip")

    return {
        "timestamp": timestamp,
        "host": data["host"],
        "process": data["process"],
        "pid": data["pid"],
        "message": message,
        "username": username,
        "source_ip": source_ip,
        "event_type": event_type,
        "command": command,
    }
