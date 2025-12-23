import os
import json
import re
import pandas as pd
from dateutil import parser
from datetime import datetime
from rich.console import Console

console = Console()

class LogIngestor:
    def __init__(self, log_dir):
        self.log_dir = log_dir
        self.data = []

    def load_logs(self):
        """Walks through the log directory and ingests supported log files."""
        if not os.path.exists(self.log_dir):
            console.print(f"[bold red]Error:[/bold red] Log directory {self.log_dir} not found.")
            return pd.DataFrame()

        for root, _, files in os.walk(self.log_dir):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    if file.endswith('.json'):
                        self._parse_json(file_path)
                    elif file.endswith('.log') or file.endswith('.txt'):
                        self._parse_text(file_path)
                    else:
                        continue # Skip unsupported
                except Exception as e:
                    console.print(f"[yellow]Warning:[/yellow] Failed to parse {file}: {e}")

        df = pd.DataFrame(self.data)
        if not df.empty:
            # Ensure timestamp is datetime
            df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True, errors='coerce')
            df = df.sort_values(by='timestamp')
        
        return df

    def _parse_json(self, file_path):
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    entry = json.loads(line)
                    # Normalize
                    norm_entry = {
                        "timestamp": self._normalize_time(entry.get("timestamp")),
                        "source_ip": entry.get("source_ip", "0.0.0.0"),
                        "user": entry.get("user", "unknown"),
                        "event": entry.get("event", "unknown"),
                        "status": entry.get("status", "unknown"),
                        "raw": line,
                        "source_file": os.path.basename(file_path)
                    }
                    self.data.append(norm_entry)
                except json.JSONDecodeError:
                    pass # Skip bad lines

    def _parse_text(self, file_path):
        # Regex for standard syslog: "Mon DD HH:MM:SS host proc: message"
        # Adjusted for the sample provided: "Dec 23 10:00:01 server-01 sshd[1234]: ..."
        # And sudo log
        
        syslog_pattern = re.compile(r'^([A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s+(.*)$')
        
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                
                match = syslog_pattern.match(line)
                if match:
                    timestamp_str, host, process, message = match.groups()
                    
                    # Attempt to extract fields from message
                    ip = "0.0.0.0"
                    user = "unknown"
                    status = "info"
                    event = "system_log"

                    # Extraction Logic (Heuristic)
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
                    if ip_match:
                        ip = ip_match.group(1)
                    
                    user_match = re.search(r'user\s+(\w+)', message) or re.search(r'USER=(\w+)', message)
                    if user_match:
                        user = user_match.group(1)

                    if "Failed password" in message:
                        event = "ssh_failed_login"
                        status = "failed"
                    elif "sudo" in process:
                        event = "sudo_execution"
                        status = "success" # Assumed unless err
                    
                    # Normalize timestamp (Add current year as syslog often misses it)
                    current_year = datetime.now().year
                    full_ts_str = f"{current_year} {timestamp_str}"
                    
                    norm_entry = {
                        "timestamp": self._normalize_time(full_ts_str),
                        "source_ip": ip,
                        "user": user,
                        "event": event,
                        "status": status,
                        "raw": line,
                        "source_file": os.path.basename(file_path)
                    }
                    self.data.append(norm_entry)

    def _normalize_time(self, ts_str):
        if not ts_str: return datetime.now()
        try:
            return parser.parse(ts_str)
        except:
            return datetime.now()
