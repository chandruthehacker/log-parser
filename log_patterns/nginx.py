import re

LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - (?P<user>\S+) \[(?P<datetime>[^\]]+)\] '  # IP, user, datetime
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '  # HTTP method, path, protocol
    r'(?P<status>\d{3}) (?P<size>\d+) "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"'  # Status, size, referrer, agent
)

def parse_log(line):
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    return match.groupdict()
