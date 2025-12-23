import pandas as pd
from datetime import timedelta

class RiskEngine:
    def __init__(self):
        pass

    def enrich_alerts(self, alerts, logs_df):
        """
        AI-Powered analysis to adjust severity and add context.
        Correlates disparate events to find complex attack patterns.
        """
        if not alerts:
            return []
            
        enriched_alerts = []
        
        # Sort alerts by time
        alerts.sort(key=lambda x: x['timestamp'])

        for alert in alerts:
            # Copy to avoid mutating original immediately
            new_alert = alert.copy()
            new_alert['ai_analysis'] = "Standard rule match."
            
            # Contextual Analysis Logic
            
            # Scenario 1: Brute Force followed by Success (Account Takeover)
            if new_alert['rule'] == 'Brute Force Attempt':
                ip = new_alert['source_ip']
                timestamp = new_alert['timestamp']
                
                # Check for successful login from same IP after this alert
                # Look ahead 10 minutes
                window_end = timestamp + timedelta(minutes=10)
                
                success_events = logs_df[
                    (logs_df['source_ip'] == ip) & 
                    (logs_df['status'] == 'success') & 
                    (logs_df['timestamp'] > timestamp) &
                    (logs_df['timestamp'] < window_end)
                ]
                
                if not success_events.empty:
                    new_alert['severity'] = "CRITICAL"
                    new_alert['ai_analysis'] = (
                        "AI CORRELATION: Brute force attack resulted in a successful authentication! "
                        "Potential Account Takeover detected."
                    )
                    new_alert['related_events'] = success_events.to_dict(orient='records')

            # Scenario 2: Sensitive File Access by Non-Privileged User
            if new_alert['rule'] == 'Sensitive File Access':
                # Check user context
                evidence = new_alert.get('evidence', [{}])[0]
                user = evidence.get('user', 'unknown')
                
                if user not in ['root', 'admin']:
                    new_alert['severity'] = "CRITICAL"
                    new_alert['ai_analysis'] = f"AI ANOMALY: Sensitive file accessed by non-standard user '{user}'."

            enriched_alerts.append(new_alert)
            
        return enriched_alerts

    def perform_rca(self, alert_id, alerts, logs_df):
        """
        Generates a human-readable Root Cause Analysis for a specific alert.
        """
        target_alert = next((a for a in alerts if a['id'] == alert_id), None)
        if not target_alert:
            return "Alert not found."
            
        ip = target_alert.get('source_ip')
        timestamp = target_alert.get('timestamp')
        
        # Build Narrative
        report_lines = []
        report_lines.append(f"RCA Report for Alert ID: {alert_id}")
        report_lines.append(f"Trigger Event: {target_alert['rule']} at {timestamp}")
        report_lines.append(f"Attacker IP: {ip}")
        report_lines.append("-" * 40)
        
        report_lines.append("SEQUENCE OF EVENTS:")
        
        # 1. Pre-Incident (Look back 1 hour)
        start_time = timestamp - timedelta(hours=1)
        pre_logs = logs_df[
            (logs_df['source_ip'] == ip) & 
            (logs_df['timestamp'] >= start_time) & 
            (logs_df['timestamp'] < timestamp)
        ]
        
        if not pre_logs.empty:
            report_lines.append(f"\n[Phase 1: Reconnaissance/Preparation]")
            summary = pre_logs['event'].value_counts().to_string()
            report_lines.append(f"observed activity from {ip} prior to alert:\n{summary}")
        else:
            report_lines.append("\n[Phase 1: Reconnaissance] No prior activity observed from this IP.")
            
        # 2. The Incident
        report_lines.append(f"\n[Phase 2: The Incident]")
        report_lines.append(f"Primary Alert: {target_alert['details']}")
        if 'ai_analysis' in target_alert:
             report_lines.append(f"AI Insight: {target_alert['ai_analysis']}")
             
        # 3. Post-Incident (Look ahead 1 hour)
        end_time = timestamp + timedelta(hours=1)
        post_logs = logs_df[
            (logs_df['source_ip'] == ip) & 
            (logs_df['timestamp'] > timestamp) & 
            (logs_df['timestamp'] <= end_time)
        ]
        
        if not post_logs.empty:
             report_lines.append(f"\n[Phase 3: Post-Exploitation/Persistence]")
             # detailed listing for post incident is crucial
             for _, row in post_logs.iterrows():
                 report_lines.append(f"- {row['timestamp']}: {row['event']} ({row['status']}) - User: {row['user']}")
        else:
             report_lines.append("\n[Phase 3] No further activity observed.")
             
        # 4. Conclusion
        report_lines.append("-" * 40)
        report_lines.append("ROOT CAUSE CONCLUSION:")
        if target_alert['severity'] == 'CRITICAL':
            report_lines.append("This is a CONFIRMED SECURITY INCIDENT. The attacker successfully bypassed defenses.")
        elif target_alert['rule'] == 'Brute Force Attempt':
             report_lines.append("The root cause is a Brute Force Attack against authentication services.")
        else:
             report_lines.append(f"The root cause appears to be {target_alert['rule']}.")
             
        return "\n".join(report_lines)
