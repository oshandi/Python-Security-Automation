import re
from collections import Counter

def parse_logs(log_file_path):
    print(f"[*] Analyzing log file: {log_file_path}")
    
    failed_logins = []
    suspicious_ips = []
    log_pattern = r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?"\s(?P<status>\d{3})'

    with open(log_file_path, 'r') as file:
        for line in file:
            match = re.search(log_pattern, line)
            if match:
                ip = match.group('ip')
                status = match.group('status')

                if status == '401':
                    failed_logins.append(ip)
                elif status == '404':
                    suspicious_ips.append(ip)

    print("\n[!] Security Alert Report:")
    print("-----------------------------------------")
    
    failed_counts = Counter(failed_logins)
    for ip, count in failed_counts.items():
        if count >= 3:
            print(f"[ALERT] Potential Brute Force Attack from: {ip} ({count} failed attempts)")

    four_o_four_counts = Counter(suspicious_ips)
    for ip, count in four_o_four_counts.items():
        print(f"[INFO] Suspicious Scanning activity from: {ip} ({count} page-not-found errors)")

if __name__ == "__main__":
    parse_logs("server_log.txt")