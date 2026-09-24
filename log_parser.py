import os
import re
import pandas as pd

class SecurityLogParser:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        # Standard Common Log Format (CLF) Regex Pattern
        self.log_pattern = r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<request>\S+)\s*[^"]*" (?P<status>\d+) (?P<size>\S+)'
        self.df = None

    def load_and_parse_logs(self):
        """Ingests raw unstructured text log and converts it to a structured Pandas DataFrame."""
        if not os.path.exists(self.log_file_path):
            raise FileNotFoundError(f"Target log file not found at: {self.log_file_path}")
        
        parsed_lines = []
        with open(self.log_file_path, 'r') as file:
            for line in file:
                match = re.match(self.log_pattern, line)
                if match:
                    parsed_lines.append(match.groupdict())
                    
        self.df = pd.DataFrame(parsed_lines)
        
        # Data Cleaning & Type Casting
        self.df['status'] = self.df['status'].astype(int)
        self.df['size'] = pd.to_numeric(self.df['size'], errors='coerce').fillna(0).astype(int)
        print(f"[+] Successfully structured {len(self.df)} raw log entries.")
        return self.df

    def analyze_threats(self, failed_login_threshold=5):
        """Executes automated heuristics to isolate and flag indicators of compromise (IoCs)."""
        if self.df is None or self.df.empty:
            print("[-] No data available to analyze.")
            return

        print("[*] Running threat detection heuristics...")

        # Heuristic 1: Brute Force Detection (Multiple 401 Unauthorized attempts from same IP)
        failed_logins = self.df[self.df['status'] == 401]
        brute_force_counts = failed_logins['ip'].value_counts()
        brute_force_ips = brute_force_counts[brute_force_counts >= failed_login_threshold].index.tolist()

        # Heuristic 2: Directory Traversal / Web Reconnaissance Attempt
        # Flag requests attempting to break out of web directories (e.g., etc/passwd or boot.ini)
        path_traversal_pattern = r'(\.\.\/|etc/passwd|win\.ini|wp-config\.php|admin)'
        traversal_attempts = self.df[self.df['request'].str.contains(path_traversal_pattern, re.IGNORECASE, regex=True)]
        malicious_ips = traversal_attempts['ip'].unique().tolist()

        # Combine all Flagged High-Risk IPs
        suspect_ips = list(set(brute_force_ips + malicious_ips))

        # Vectorized Alert Labeling inside the main DataFrame
        self.df['risk_score'] = 0
        self.df['threat_label'] = 'Benign Traffic'

        # Apply Risk Metrics
        self.df.loc[self.df['ip'].isin(suspect_ips), 'risk_score'] = 7
        self.df.loc[self.df['ip'].isin(suspect_ips), 'threat_label'] = 'Suspicious Activity Detected'
        
        # Explicit labeling for high-confidence patterns
        self.df.loc[self.df['request'].str.contains(path_traversal_pattern, re.IGNORECASE, regex=True), 'risk_score'] = 10
        self.df.loc[self.df['request'].str.contains(path_traversal_pattern, re.IGNORECASE, regex=True), 'threat_label'] = 'Critical: Web Exploit Attempt'

        total_alerts = len(self.df[self.df['risk_score'] > 0])
        print(f"[!] Security Analysis complete. Isolated {total_alerts} security alerts.")

    def export_incident_report(self, output_csv_path):
        """Outputs a clean, structured security alert CSV for SIEM integration or triage teams."""
        if self.df is None:
            print("[-] Export failed. No data compiled.")
            return
        
        # Filter for entries that require active human intervention / Tier 1 triage
        incident_report = self.df[self.df['risk_score'] > 0].sort_values(by='risk_score', ascending=False)
        incident_report.to_csv(output_csv_path, index=False)
        print(f"[+] Incident triage report successfully generated at: {output_csv_path}")


# Executable Sandbox for Testing
if __name__ == "__main__":
    # Create a mock log file locally to demonstrate script performance
    mock_log_data = """192.168.1.50 - - [22/Sep/2026:14:32:10 +0100] "GET /index.html HTTP/1.1" 200 4523
203.0.113.5 - - [22/Sep/2026:14:33:01 +0100] "POST /login.php HTTP/1.1" 401 230
203.0.113.5 - - [22/Sep/2026:14:33:05 +0100] "POST /login.php HTTP/1.1" 401 230
203.0.113.5 - - [22/Sep/2026:14:33:10 +0100] "POST /login.php HTTP/1.1" 401 230
203.0.113.5 - - [22/Sep/2026:14:33:15 +0100] "POST /login.php HTTP/1.1" 401 230
203.0.113.5 - - [22/Sep/2026:14:33:20 +0100] "POST /login.php HTTP/1.1" 401 230
198.51.100.12 - - [22/Sep/2026:14:35:22 +0100] "GET /etc/passwd HTTP/1.1" 404 120
192.168.1.72 - - [22/Sep/2026:14:36:00 +0100] "GET /images/logo.png HTTP/1.1" 200 12045"""

    with open("sample_access.log", "w") as f:
        f.write(mock_log_data.strip())

    # Initialize Pipeline
    analyzer = SecurityLogParser("sample_access.log")
    analyzer.load_and_parse_logs()
    analyzer.analyze_threats(failed_login_threshold=5)
    analyzer.export_incident_report("security_alerts_triage.csv")