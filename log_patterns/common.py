from datetime import datetime

# Convert Apache and Nginx log datetime format to ISO format
def parse_common_log_datetime(dt_str):
    """
    Converts date from format: 10/Oct/2000:13:55:36 -0700
    To ISO format: 2000-10-10 13:55:36
    """
    try:
        dt_obj = datetime.strptime(dt_str.split()[0], "%d/%b/%Y:%H:%M:%S")
        return dt_obj.isoformat(sep=" ")
    except Exception:
        return dt_str
