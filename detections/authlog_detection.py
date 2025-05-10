from collections import defaultdict

def authlog_detection(logs):
    # Initialize result dictionary to store different types of alerts
    result = {
        "Brute-Force SSH Attack": [],
        "Suspicious Login Times": [],
        "Logins from New or Rare IPs": [],
        "Multiple Failed Then Successful Login": [],
        "Sudden Sudo Access": []
    }

    # Counters for tracking login attempts
    brute_force_counter = defaultdict(int)
    known_user_ips = defaultdict(set)
    failed_before_success = defaultdict(int)

    # Process each log entry
    for entry in logs:
        ip = entry.get("source_ip")
        user = entry.get("username")
        status = entry.get("status")
        timestamp = entry.get("timestamp")
        event_type = entry.get("event_type")
        command = entry.get("command")
        if not ip or not user or not status:
            # Sudden sudo access detection
            if event_type == "sudo" and command:
                result["Sudden Sudo Access"].append(
                    f"{user} ran sudo command '{command}' at {timestamp}"
                )
            continue  # Skip incomplete logs
        
        

        # Brute-force SSH detection
        if status == "Failed":
            brute_force_counter[ip] += 1
            failed_before_success[ip] += 1
            if brute_force_counter[ip] > 3:
                result["Brute-Force SSH Attack"].append(
                    f"{ip} failed to login {brute_force_counter[ip]} times (possible brute-force)"
                )

        elif status == "Accepted":
            # Suspicious login time detection (e.g., late-night logins)
            hour = int(timestamp.split(" ")[1].split(":")[0])
            if hour < 6 or hour > 23:
                result["Suspicious Login Times"].append(
                    f"{user} logged in from {ip} at odd hour {hour}:00 ({timestamp})"
                )

            # Logins from new or rare IP detection
            if ip not in known_user_ips[user]:
                result["Logins from New or Rare IPs"].append(
                    f"New IP {ip} used by {user} at {timestamp}"
                )
                known_user_ips[user].add(ip)

            # Successful login after multiple failed attempts
            if failed_before_success[ip] >= 3:
                result["Multiple Failed Then Successful Login"].append(
                    f"{ip} user {user} succeeded login after {failed_before_success[ip]} failures"
                )
            failed_before_success[ip] = 0

        

    return result
