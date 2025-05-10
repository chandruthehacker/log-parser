from detections.apache_detection import apache_detection
from detections.authlog_detection import authlog_detection
from detections.nginx_detection import nginx_detection
from detections.syslog_detection import syslog_detection


def log_detection(parsed_logs, log_type):
    """
    Master detection handler. Dispatches detection to correct log type.
    :param parsed_logs: List of parsed log dictionaries
    :param log_type: String representing log type ('authlog', 'apache', 'nginx', etc.)
    """
    if not parsed_logs or not isinstance(parsed_logs, list):
        print("No logs to analyze or format is incorrect.")
        return

    if log_type == "authlog":
        return authlog_detection(parsed_logs)

    elif log_type == "apache":
        return apache_detection(parsed_logs)

    elif log_type == "nginx":
        return nginx_detection(parsed_logs)

    elif log_type == "syslog":
        return syslog_detection(parsed_logs)

    else:
        print(f"❌ Unsupported log type: {log_type}")
        return