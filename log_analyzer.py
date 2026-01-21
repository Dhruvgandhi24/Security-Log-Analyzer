import re
from collections import defaultdict

LOG_FILE = "sample_logs.txt"
FAILED_LOGIN_THRESHOLD = 3

failed_logins = defaultdict(int)
suspicious_users = set()
error_events = 0
total_logs = 0

log_pattern = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})\s"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s"
    r"(?P<level>INFO|WARNING|ERROR)\s"
    r"(?P<message>.+?)\s\|\suser=(?P<user>\w+)\s\|\sip=(?P<ip>[\d\.]+)"
)

try:
    with open(LOG_FILE, "r") as file:
        for line in file:
            total_logs += 1
            match = log_pattern.search(line)

            if not match:
                continue

            level = match.group("level")
            user = match.group("user")
            ip = match.group("ip")
            message = match.group("message")

            if "Failed login attempt" in message:
                failed_logins[ip] += 1

            if user.lower() in ["unknown", "guest"]:
                suspicious_users.add((user, ip))

            if level == "ERROR":
                error_events += 1

except FileNotFoundError:
    print("[-] Log file not found. Make sure sample_logs.txt exists.")
    exit()

print("\n===== Security Log Analysis Report =====\n")
print(f"Total log entries analyzed: {total_logs}\n")

print("Suspicious Failed Login Attempts:")
for ip, count in failed_logins.items():
    if count >= FAILED_LOGIN_THRESHOLD:
        print(f" - IP {ip} had {count} failed login attempts")

print("\nSuspicious User Activity:")
for user, ip in suspicious_users:
    print(f" - User '{user}' accessed system from IP {ip}")

print(f"\nTotal ERROR-level security events: {error_events}")
print("\n===== End of Report =====")