from collections import defaultdict
from datetime import datetime, timedelta

def syslog_detection(logs):
    result = {
        "Unexpected Service Restarts": [],
        "Unauthorized Access Attempts": [],
        "Frequent System Errors": [],
        "Cron Job Injection Attempts": [],
        "Repeated Authentication Failures": []
    }

    restart_keywords = ["restart", "restarted", "start", "stopped", "failed to start"]
    auth_fail_keywords = ["authentication failure", "failed password", "invalid user", "failed login"]
    unauth_access_keywords = ["incorrect password attempts", "password attempts", "incorrect password"]
    cron_keywords = ["cron", "crontab", "cronjob"]
    suspicious_cron_patterns = ["*/1 * * * *", "@reboot", "wget", "curl", "bash", "python", "sh"]

    auth_fail_counter = defaultdict(int)
    service_restart_counter = defaultdict(int)
    system_error_counter = defaultdict(int)

    for log in logs:
        timestamp_str = log.get("timestamp")
        process = log.get("process", "").lower()
        message = log.get("message", "").lower()
        host = log.get("host")
        ip = log.get("source_ip") or "Unknown"

        try:
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        except:
            continue

        # Detect service restarts
        if any(keyword in message for keyword in restart_keywords):
            service_restart_counter[host] += 1
            result["Unexpected Service Restarts"].append(
                f"{host}: Detected service restart ('{message}') at {timestamp_str}"
            )

        # Detect authentication failures
        if any(keyword in message for keyword in auth_fail_keywords):
            auth_fail_counter[ip] += 1
            if auth_fail_counter[ip] >= 3:
                result["Repeated Authentication Failures"].append(
                    f"{ip} had {auth_fail_counter[ip]} failed authentication attempts"
                )
                
        # Detect unauthorized attempts
        if any(keyword in message for keyword in unauth_access_keywords):
            result["Unauthorized Access Attempts"].append(
                f"{message}"
            )

        # Detect system errors
        if "error" in message or "panic" in message or "kernel" in process:
            system_error_counter[host] += 1
            if system_error_counter[host] >= 3:
                result["Frequent System Errors"].append(
                    f"{host} reported frequent system errors (3+) as of {timestamp_str}"
                )

        # Detect cron job injection
        if any(cron_kw in process for cron_kw in cron_keywords):
            if any(inject in message for inject in suspicious_cron_patterns):
                result["Cron Job Injection Attempts"].append(
                    f"Suspicious cron job on {host}: '{message}' at {timestamp_str}"
                )

    return result
