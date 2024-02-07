import pandas as pd
import re

def parse_log_file(file_path):
    # Read the log file content
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        log_file_content = file.read()

    # Define a regular expression pattern for log parsing
    log_pattern = re.compile(r'(?P<ip>[\d.]+)\s-\s-\s\[(?P<timestamp>.*?)\]\s"(?P<method>[A-Z]+)\s(?P<url>.*?)\sHTTP/\d+\.\d+"\s(?P<status>\d+)\s(?P<size>\d+)\s"(?P<referer>.*?)"\s"(?P<user_agent>.*?)"')

    # Parse log entries
    log_entries = [match.groupdict() for match in log_pattern.finditer(log_file_content)]

    # Create a DataFrame with specific columns
    df = pd.DataFrame(log_entries, columns=["ip", "timestamp", "method", "url", "status", "size", "referer", "user_agent"])

    return df

