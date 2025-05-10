import pandas as pd
import json
import os

# Ensure output folder exists
os.makedirs("output", exist_ok=True)

# Save parsed logs and alerts to CSV
def save_to_csv(parsed_logs, alerts):
    pd.DataFrame(parsed_logs).to_csv('output/parsed_logs.csv', index=False)
    print("[+] Logs saved to output/parsed_logs.csv")

    pd.DataFrame(alerts).to_csv('output/alerts.csv', index=False)
    print("[+] Alerts saved to output/alerts.csv")


# Save parsed logs and alerts to Excel
def save_to_excel(parsed_logs, alerts):
    with pd.ExcelWriter('output/parsed_logs.xlsx') as writer:
        pd.DataFrame(parsed_logs).to_excel(writer, sheet_name="ParsedLogs", index=False)
        pd.DataFrame(alerts).to_excel(writer, sheet_name="Alerts", index=False)
    print("[+] Logs & Alerts saved to output/parsed_logs.xlsx")


# Save parsed logs and alerts to JSON
def save_to_json(parsed_logs, alerts):
    with open("output/parsed_logs.json", "w") as json_file:
        json.dump(parsed_logs, json_file, indent=4)
    print("[+] Logs saved to output/parsed_logs.json")

    with open("output/alerts.json", "w") as alert_file:
        json.dump(alerts, alert_file, indent=4)
    print("[+] Alerts saved to output/alerts.json")


# Print parsed logs and alerts to CLI
def print_to_cli(parsed_logs, alerts):
    print("=== Parsed Logs ===")
    for log in parsed_logs:
        print(f"Timestamp: {log.get('timestamp')}")
        print(f"Host: {log.get('host')}")
        print(f"Process: {log.get('process')}")
        print(f"Message: {log.get('message')}")
        print("-" * 50)

    print("\n=== Alerts ===")
    with open("output/alerts.json", "w") as alert_file:
        json.dump(alerts, alert_file, indent=4)
    print("[+] Alerts saved to output/alerts.json")
