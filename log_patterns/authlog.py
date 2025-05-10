import re
from datetime import datetime

LOG_PATTERN = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}) '
    r'(?P<host>\S+) (?P<process>[^\[]+)(\[(?P<pid>\d+)\])?: (?P<message>.+)'
)

SSH_REGEX = re.compile(
    r'(?P<status>Failed|Accepted) (?P<auth_method>password|publickey) for (invalid user )?(?P<username>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)'
)

SUDO_REGEX = re.compile(
    r'TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.+)'
)

def parse_log(log_line):
    match = LOG_PATTERN.match(log_line)
    if not match:
        return None

    data = match.groupdict()
    try:
        current_year = datetime.now().year
        timestamp = datetime.strptime(
            f"{data['month']} {data['day']} {current_year} {data['time']}",
            "%b %d %Y %H:%M:%S"
        ).isoformat(sep=" ")
    except ValueError:
        timestamp = f"{data['month']} {data['day']} {data['time']}"

    result = {
        "timestamp": timestamp,
        "host": data["host"],
        "process": data["process"].strip(),
        "pid": data.get("pid", ""),
        "message": data["message"],
        "source_ip": None,
        "username": None,
        "auth_method": None,
        "status": None,
        "port": None,
        "event_type": "unknown",
        "tty": None,
        "pwd": None,
        "target_user": None,
        "command": None
    }

    ssh_match = SSH_REGEX.search(data["message"])
    if ssh_match:
        ssh_data = ssh_match.groupdict()
        result.update({
            "source_ip": ssh_data["ip"],
            "username": ssh_data["username"],
            "auth_method": ssh_data["auth_method"],
            "status": ssh_data["status"],
            "port": ssh_data["port"],
            "event_type": "ssh"
        })
    elif "sudo" in data["process"].lower():
        sudo_match = SUDO_REGEX.search(data["message"])
        if sudo_match:
            sudo_data = sudo_match.groupdict()
            result.update({
                "event_type": "sudo",
                "tty": sudo_data["tty"],
                "pwd": sudo_data["pwd"],
                "target_user": sudo_data["target_user"],
                "command": sudo_data["command"].strip()
            })
        # Attempt to extract username from process field (e.g., "sudo:  user1")
        process_parts = data["process"].split(":")
        if len(process_parts) > 1:
            result["username"] = process_parts[1].strip().split()[0]
        # Alternatively, try to extract the invoking user from the message (less reliable format)
        sudo_user_match = re.search(r'^(?:\S+\s+){2,3}(\S+)\s+:', data["message"]) # Example pattern
        if result.get("username") is None and sudo_user_match:
            result["username"] = sudo_user_match.group(1)

    return result

