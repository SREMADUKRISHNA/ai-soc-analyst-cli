import pandas as pd
import uuid
from datetime import timedelta

class DetectionEngine:
    def __init__(self):
        self.alerts = []

    def run_detection(self, df):
        """Runs all detection rules on the dataframe."""
        if df.empty:
            return []

        self.alerts = []
        
        # Rule 1: Brute Force Detection
        self._detect_brute_force(df)
        
        # Rule 2: Sensitive File Access
        self._detect_sensitive_access(df)
        
        # Rule 3: Root/Admin Activity
        self._detect_privileged_activity(df)

        return self.alerts

    def _detect_brute_force(self, df):
        """Detects > 3 failed logins from same IP within 5 minutes."""
        failed_logins = df[df['status'] == 'failed'].copy()
        if failed_logins.empty:
            return

        # Group by IP and resample 5min windows
        # We need to set index to timestamp for resampling
        failed_logins.set_index('timestamp', inplace=True)
        
        # Count failures per IP per 5min
        # Use grouping by IP then resample
        # Logic: Iterate unique IPs to avoid complex multi-index handling for now or use groupby timegrouper
        
        for ip in failed_logins['source_ip'].unique():
            ip_data = failed_logins[failed_logins['source_ip'] == ip]
            # Resample count
            counts = ip_data.resample('5min').size()
            
            # Check if any window > 3
            for ts, count in counts.items():
                if count >= 3:
                    alert_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{ts}{ip}Brute Force Attempt"))[:8]
                    self.alerts.append({
                        "id": alert_id,
                        "rule": "Brute Force Attempt",
                        "timestamp": ts,
                        "source_ip": ip,
                        "details": f"Detected {count} failed login attempts within 5 minutes.",
                        "severity": "Medium", # Initial severity
                        "evidence": ip_data.head(count).to_dict(orient='records') # Attach sample logs
                    })

    def _detect_sensitive_access(self, df):
        """Detects access to sensitive files."""
        sensitive_files = ['/etc/shadow', '/etc/passwd', 'C:\\Windows\\System32\\config\\SAM']
        
        # Filter for sensitive keywords in 'raw' or 'event'
        # Simple string matching for this demo
        for index, row in df.iterrows():
            raw_log = row.get('raw', '')
            for sens_file in sensitive_files:
                if sens_file in raw_log:
                    alert_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{row['timestamp']}{row['source_ip']}Sensitive File Access"))[:8]
                    self.alerts.append({
                        "id": alert_id,
                        "rule": "Sensitive File Access",
                        "timestamp": row['timestamp'],
                        "source_ip": row['source_ip'],
                        "details": f"Access detected to sensitive file: {sens_file}",
                        "severity": "High",
                        "evidence": [row.to_dict()]
                    })
                    break # Trigger once per log line

    def _detect_privileged_activity(self, df):
        """Detects root/admin successful logins."""
        crit_users = ['root', 'admin', 'administrator']
        
        subset = df[(df['user'].isin(crit_users)) & (df['status'] == 'success')]
        
        for index, row in subset.iterrows():
            alert_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{row['timestamp']}{row['source_ip']}Privileged User Login"))[:8]
            self.alerts.append({
                "id": alert_id,
                "rule": "Privileged User Login",
                "timestamp": row['timestamp'],
                "source_ip": row['source_ip'],
                "details": f"Successful login by privileged user: {row['user']}",
                "severity": "Low", # Usually normal, but worth noting
                "evidence": [row.to_dict()]
            })

    def deduplicate_alerts(self):
        """Merges similar alerts (same rule, same IP, close time)."""
        # (Optional implementation for refinement)
        pass
