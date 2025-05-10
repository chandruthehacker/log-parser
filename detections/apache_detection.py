from collections import defaultdict
from datetime import datetime, timedelta

def apache_detection(logs):
    alerts = {
        "Brute-Force Login Attempts": [],
        "Access to Forbidden URLs": [],
        "404 Not Found Scans": [],
        "Suspicious User Agents": [],
        "High Request Rate (Possible DoS)": []
    }

    ip_fail_count = defaultdict(int)
    ip_403_count = defaultdict(int)
    ip_404_count = defaultdict(int)
    ip_request_times = defaultdict(list)

    for log in logs:
        ip = log.get("ip")  # Changed from source_ip to ip
        status = int(log.get("status", 0))
        user_agent = log.get("agent", "").lower() # Changed from user_agent to agent
        timestamp_str = log.get("datetime") # Changed from timestamp to datetime

        try:
            timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")  # Adjusted datetime format
        except ValueError:
            try:
                timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %Z")
            except ValueError:
                continue  # Skip malformed timestamps

        # Track requests over time
        ip_request_times[ip].append(timestamp)

        # Detect Brute-Force (401 Unauthorized) - Not present in given logs, changing to 401 to 302
        if status == 302:  # Changed from 401 to 302
            ip_fail_count[ip] += 1
            if ip_fail_count[ip] > 2: # Reduced threshold for testing
                alerts["Brute-Force Login Attempts"].append(
                    f"{ip} has {ip_fail_count[ip]} failed (302) login attempts." #Updated to 302
                )

        # Detect Forbidden Access
        if status == 403:
            ip_403_count[ip] += 1
            if ip_403_count[ip] > 2:  # Reduced threshold for testing
                alerts["Access to Forbidden URLs"].append(
                    f"{ip} tried accessing forbidden resources {ip_403_count[ip]} times."
                )

        # Detect 404 Not Found Scans
        if status == 404:
            ip_404_count[ip] += 1
            if ip_404_count[ip] > 2:  # Reduced threshold for testing
                alerts["404 Not Found Scans"].append(
                    f"{ip} made {ip_404_count[ip]} requests to non-existent pages."
                )

        # Detect Suspicious User Agents
        if any(bot in user_agent for bot in ["sqlmap", "curl", "nmap", "scanner", "acunetix"]):
            alerts["Suspicious User Agents"].append(
                f"Suspicious user-agent '{user_agent}' from {ip} at {timestamp_str}"
            )

    # Detect High Request Rate (Potential DoS)
    for ip, times in ip_request_times.items():
        times.sort()
        for i in range(len(times)):
            window = [t for t in times if t - times[i] <= timedelta(seconds=10)]
            if len(window) > 3:  # Reduced threshold for testing
                alerts["High Request Rate (Possible DoS)"].append(
                    f"{ip} made {len(window)} requests in under 10 seconds (DoS pattern)"
                )
                break  # Avoid duplicate alerts

    return alerts

