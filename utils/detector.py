import os
from log_patterns.apache import LOG_PATTERN as apache_pattern
from log_patterns.nginx import LOG_PATTERN as nginx_pattern
from log_patterns.syslog import LOG_PATTERN as syslog_pattern
from log_patterns.authlog import LOG_PATTERN as authlog_pattern

def detect_log_type(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"The file {file_path} does not exist.")
    
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            if apache_pattern.match(line):
                return "apache"
            elif nginx_pattern.match(line):
                return "nginx"
            elif authlog_pattern.match(line):
                return "authlog"
            elif syslog_pattern.match(line):
                return "syslog"
    
    raise ValueError(f"Unknown log type: Unable to match any known format for {file_path}")
