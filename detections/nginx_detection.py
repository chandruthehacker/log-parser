from collections import defaultdict
from datetime import datetime, timedelta
import json

def nginx_detection(logs):
    result = {
        "Repeated 4xx/5xx Errors": [],
        "Sensitive File Access Attempts": [],
        "High Request Rate (Possible DoS)": [],
        "Suspicious User Agents": []
    }

    error_count = defaultdict(lambda: {"4xx": 0, "5xx": 0})
    request_times = defaultdict(list)
    suspicious_files = [".env", ".git", "config.php", "wp-config.php", "/etc/passwd"]
    user_agent_hits = []

    for log in logs:
        ip = log.get("ip")  # Changed from source_ip
        status = int(log.get("status", 0))
        uri = log.get("path", "").lower()  # Changed from uri
        timestamp_str = log.get("datetime")  # Changed from timestamp
        user_agent = log.get("agent", "").lower()  # Changed from user_agent

        try:
            timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %Z")
            except ValueError:
                continue  # skip malformed timestamps

        # Track request rate
        request_times[ip].append(timestamp)

        # Count error status codes
        if 400 <= status < 500:
            error_count[ip]["4xx"] += 1
        elif 500 <= status < 600:
            error_count[ip]["5xx"] += 1

        # Sensitive file access
        if any(sensitive in uri for sensitive in suspicious_files):
            result["Sensitive File Access Attempts"].append(
                f"{ip} tried to access sensitive file '{uri}' at {timestamp_str}"
            )

        # Suspicious User Agent
        if any(s in user_agent for s in ["sqlmap", "nmap", "curl", "scanner", "dirbuster", "acunetix", "python-requests", "postman"]): #Added
            result["Suspicious User Agents"].append(
                f"Suspicious user-agent '{user_agent}' from {ip} at {timestamp_str}"
            )

    # Check for brute-force style 4xx/5xx
    for ip, counts in error_count.items():
        if counts["4xx"] >= 3:  # Reduced threshold
            result["Repeated 4xx/5xx Errors"].append(f"{ip} had {counts['4xx']} 4xx errors.")
        if counts["5xx"] >= 2:  # Reduced threshold
            result["Repeated 4xx/5xx Errors"].append(f"{ip} had {counts['5xx']} 5xx errors.")

    # Detect DoS-style request spikes
    for ip, times in request_times.items():
        times.sort()
        for i in range(len(times)):
            window = [t for t in times if t - times[i] <= timedelta(seconds=10)]
            if len(window) > 5:  # Reduced threshold
                result["High Request Rate (Possible DoS)"].append(
                    f"{ip} made {len(window)} requests in under 10 seconds."
                )
                break  # prevent duplicate alerts

    return result
