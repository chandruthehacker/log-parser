import time
import argparse
from halo import Halo
import pyfiglet
from detections.detection import log_detection
from utils.detector import detect_log_type
from utils.output import save_to_csv, save_to_excel, save_to_json, print_to_cli
from utils.visualizer import generate_visualization
from log_patterns import log_modules

def parse_log_file(filename, log_type):
    parser_module = log_modules.get(log_type)
    if not parser_module:
        raise ValueError(f"Parser for log type '{log_type}' not found.")

    with open(filename, 'r') as file:
        lines = file.readlines()

    parsed_data = []
    for line in lines:
        parsed_line = parser_module.parse_log(line)
        if parsed_line:
            parsed_data.append(parsed_line)

    if not parsed_data:
        raise ValueError("No valid log entries were parsed.")
    
    return parsed_data


def main():
    parser = argparse.ArgumentParser(description="Universal Log File Parser Tool")
    parser.add_argument("-f", "--file", required=True, help="Log file's path")
    parser.add_argument("-t", "--type", choices=["authlog", "syslog", "apache","nginx"], help="Log file's type")
    parser.add_argument("-o", "--output", default="cli", choices=["csv", "excel", "matplotlib","json","cli"],
                        help="Output format (default: cli)")

    args = parser.parse_args()
    filename = args.file
    output_format = args.output

    try:
        log_type = None
        if args.type:
            log_type = args.type
            print(f"[+] Log type: {log_type}")
        else:
            print("[*] Detecting log type...")
            log_type = detect_log_type(filename)
            print(f"[+] Detected log type: {log_type}")

        print("[*] Parsing log file...")
        parsed_logs = parse_log_file(filename, log_type)
        print(f"[+] Parsed {len(parsed_logs)} log entries.")

        spinner = Halo(text='Generating output...', spinner='dots')
        spinner.start()
        time.sleep(1)
        alerts = log_detection(parsed_logs, log_type)


        print("\n")
        
        if output_format == "csv":
            save_to_csv(parsed_logs, alerts)
        elif output_format == "excel":
            save_to_excel(parsed_logs, alerts)
        elif output_format == "matplotlib":
            generate_visualization(parsed_logs, alerts)
        elif output_format == "json":
            save_to_json(parsed_logs, alerts)
        elif output_format == "cli":
            print_to_cli(parsed_logs, alerts)

        spinner.succeed("Log parsing complete!")

    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    ascii_banner = pyfiglet.figlet_format("Log Parser")
    print(ascii_banner)
    print("\t\t- By chandruthehacker\n\n")
    spinner = Halo(text='Initializing tool...', spinner='dots')
    spinner.start()
    time.sleep(2)
    spinner.succeed('Ready!')
    main()
