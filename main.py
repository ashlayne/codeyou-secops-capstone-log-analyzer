# region imports
import os
import sys
from enum import Enum
from collections import Counter, defaultdict
import ipaddress
import csv
# endregion

# region dictionary for file parsing to account for case insensitivity
# This is to help this script run with expected behaviour using an OS-agnostic approach
def find_file_case_insensitive(filename: str, search_dir: str = ".") -> str | None: 
    target_lower = filename.strip().lower()

    for entry in os.listdir(search_dir):
        if entry.lower() == target_lower:
            return os.path.join(search_dir, entry)  # Returns actual path on disk

    return None
# endregion

#region previewing alert types
def find_alert_types(filepath: str) -> Counter:
    alert_counts = Counter()

    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue  # Skip empty lines

            parts = line.split()
            
            # Ensure the line has at least the timestamp and alert type columns
            if len(parts) >= 2:
                alert_type = parts[1]
                alert_counts[alert_type] += 1
            else:
                print(f"Warning: Line {line_num} malformed: '{line}'")

    return alert_counts
#endregion

#region Enum mapping
class AlertType(Enum):
    AUTH_SUCCESS = "auth_success"
    AUTH_FAIL = "auth_fail"
    PRIV_CHANGE = "priv_change"
#endregion

#region Alert class
class Alert:
    def __init__(self, date, alert_type: AlertType, username, ip_address, message):
            self.date = date
            self.alert_type = alert_type
            self.username = username
            self.ip_address = ip_address
            self.message = message

    def severity(self):
        if self.alert_type == AlertType.AUTH_SUCCESS:
            return "Successful login"
        if self.alert_type == AlertType.AUTH_FAIL:
            return "Failed login"
        if self.alert_type == AlertType.PRIV_CHANGE:
            return "Privilege change"
        return "Unknown severity"

    def __str__(self):
        return (
            f"{self.date} \n"
            f"  {self.alert_type.value} on {self.username} -> {self.message}"
        )
#endregion

#region failed logins
def detect_failed_login_spikes(alerts: list[Alert], threshold: int = 3) -> dict[tuple[str, str], int]:
    #Counts failed login attempts grouped by (username, ip_address) and returns those exceeding the threshold.
    failed_counts = Counter()

    for alert in alerts:
        if alert.alert_type == AlertType.AUTH_FAIL:
            # Group by the pair of (username, ip_address)
            failed_counts[(alert.username, alert.ip_address)] += 1

    # Filter out entries that haven't reached the threshold
    flagged = {
        user_ip: count 
        for user_ip, count in failed_counts.items() 
        if count >= threshold
    }

    return flagged
#endregion

#region failed logins by user
def count_failed_logins_by_user(alerts: list[Alert], threshold: int = 3) -> dict[str, int]:
    """Counts total failed login attempts per username."""
    user_counts = Counter()
    for alert in alerts:
        if alert.alert_type == AlertType.AUTH_FAIL:
            user_counts[alert.username] += 1
    return {user: count for user, count in user_counts.items() if count >= threshold}
#endregion

#region failures followed by success
def detect_brute_force(alerts: list[Alert], min_failures: int = 3) -> list[dict]:
    # Detects instances where a user has 'min_failures' or more failed logins followed immediately by a successful login.
    
    # Group alerts chronologically by username
    user_logs = defaultdict(list)
    for alert in alerts:
        user_logs[alert.username].append(alert)

    suspicious_events = []

    for username, user_alerts in user_logs.items():
        consecutive_fails = 0
        failed_ips = set()

        for alert in user_alerts:
            if alert.alert_type == AlertType.AUTH_FAIL:
                consecutive_fails += 1
                failed_ips.add(alert.ip_address)

            elif alert.alert_type == AlertType.AUTH_SUCCESS:
                # Check if this success came after threshold failures
                if consecutive_fails >= min_failures:
                    suspicious_events.append({
                        "username": username,
                        "fail_count": consecutive_fails,
                        "success_time": alert.date,
                        "success_ip": alert.ip_address,
                        "fail_ips": list(failed_ips)
                    })

                # Reset counter after a success
                consecutive_fails = 0
                failed_ips = set()

            else:
                # If there are other alert types (like PRIV_CHANGE), you can choose to reset or ignore
                pass

    return suspicious_events
#endregion

#region external IP addresses
def detect_external_ips(alerts: list[Alert], internal_ranges: list[str] = None) -> list[Alert]:
    #Returns a list of alerts that originated from external (public) IP addresses.
    external_alerts = []
    if internal_ranges is None:
        # Default internal ranges (or custom CIDRs)
        internal_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]

    # Convert range strings to ip_network objects once for efficiency
    networks = [ipaddress.ip_network(cidr) for cidr in internal_ranges]
    external_alerts = []

    for alert in alerts:
        if alert.alert_type == AlertType.AUTH_SUCCESS:
            continue

        try:
            ip_obj = ipaddress.ip_address(alert.ip_address)
            is_internal = any(ip_obj in net for net in networks)
            if not is_internal:
                external_alerts.append(alert)
        except ValueError:
            # Handle invalid IP address formats if necessary
            continue

    return external_alerts
#endregion

#region Privilege Escalation 
def detect_privilege_escalation(alerts: list[Alert]) -> list[Alert]:
    """
    Flags alerts related to privilege escalation based on AlertType or 
    keywords in the alert message.
    """
    keywords = [
        "sudo",
        "admin",
        "administrator",
        "root",
        "privilege",
        "elevated",
        "added to group"
    ]

    flagged_alerts = []

    for alert in alerts:
        msg_lower = alert.message.lower()

        # Flag if the alert type is PRIV_CHANGE or if any keyword matches the message
        is_priv_enum = alert.alert_type == AlertType.PRIV_CHANGE
        has_keyword = any(keyword in msg_lower for keyword in keywords)

        if is_priv_enum or has_keyword:
            flagged_alerts.append(alert)

    return flagged_alerts
#endregion

#region failed logins by ip
def count_failed_logins_by_ip(alerts: list[Alert], threshold: int = 3) -> dict[str, int]:
    """Counts total failed logins per IP address across all usernames."""
    ip_counts = Counter()
    for alert in alerts:
        if alert.alert_type == AlertType.AUTH_FAIL:
            ip_counts[alert.ip_address] += 1
    return {ip: count for ip, count in ip_counts.items() if count >= threshold}
#endregion

#region ips on multiple users
def detect_ips_touching_multiple_users(alerts: list[Alert], min_users: int = 2) -> dict[str, set[str]]:
    """Identifies single IP addresses targeting multiple distinct usernames (Password Spraying)."""
    ip_to_users = defaultdict(set)
    for alert in alerts:
        if alert.alert_type == AlertType.AUTH_FAIL:
            ip_to_users[alert.ip_address].add(alert.username)
    return {ip: users for ip, users in ip_to_users.items() if len(users) >= min_users}
#endregion

#region csv export setup
def export_flagged_events_to_csv(
    filename: str,
    flagged_attempts: dict,
    flagged_breaches: list,
    external_attempts: list,
    priv_escalations: list
):
    """Exports all flagged security events into a structured CSV file."""
    
    headers = ["Category", "Username", "IP Address", "Timestamp", "Details"]

    with open(filename, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(headers)

        # 1. Repeated Failed Login Spikes
        for (user, ip), count in flagged_attempts.items():
            writer.writerow([
                "Failed Login Spike",
                user,
                ip,
                "N/A",
                f"{count} failed login attempts"
            ])

        # 2. Critical Brute Force (3+ Fails followed by Success)
        for breach in flagged_breaches:
            writer.writerow([
                "Brute Force Pattern",
                breach["username"],
                breach["success_ip"],
                breach["success_time"],
                f"{breach['fail_count']} fails prior to success. Attacking IPs: {', '.join(breach['fail_ips'])}"
            ])

        # 3. External IP Activity
        for alert in external_attempts:
            writer.writerow([
                "External IP Activity",
                alert.username,
                alert.ip_address,
                alert.date,
                f"Alert Type: {alert.alert_type.name} | Msg: {alert.message}"
            ])

        # 4. Privilege Escalation Events
        for alert in priv_escalations:
            writer.writerow([
                "Privilege Escalation",
                alert.username,
                alert.ip_address,
                alert.date,
                f"Msg: {alert.message}"
            ])
#endregion

def main():

    # region filename collector
    filename = ""

    while not os.path.exists(filename):
        user_input = input("Please enter the filename in this directory you wish to review (or type quit to exit): ")

        if user_input.lower() == "quit":
            sys.exit()

        filename = find_file_case_insensitive(user_input)

        if not os.path.exists(filename):
            print(f"Error: No such filename {filename}. Please try again.")
    # endregion

    #region file preview
    with open(filename, "r", encoding="UTF-8") as f:
         lines = f.read().splitlines()

    print(f"Loaded {len(lines)} alerts.")

    print(f"\n--- Processing '{filename}' ---")
    alert_summary = find_alert_types(filename)

    # No longer needed, leaving in for historical analysis
    # print("=" * 30)
    # print("\nAlert Types Summary:")
    # print("=" * 30)
    # for alert_type, count in alert_summary.most_common():
    #     print(f"{alert_type:<20} : {count}")
    #endregion

    alerts = []

    for line in lines:
        parts = line.split(maxsplit=4)
        if len(parts) < 5:
            continue

        date = parts[0]
        alert_type_str = parts[1]
        username = parts[2].replace("user=", "")
        ip_address = parts[3].replace("ip=", "")
        message = parts[4].replace("message=", "")

        # Look up Enum member by name (e.g., 'AUTH_SUCCESS') safely
        try:
            alert_type = AlertType[alert_type_str]
        except KeyError:
            continue  # Skip if alert_type isn't in Enum

        new_alert = Alert(date, alert_type, username, ip_address, message)
        alerts.append(new_alert)

    auth_success = sum(1 for a in alerts if a.alert_type == AlertType.AUTH_SUCCESS)
    auth_fail = sum(1 for a in alerts if a.alert_type == AlertType.AUTH_FAIL)
    priv_change = sum(1 for a in alerts if a.alert_type == AlertType.PRIV_CHANGE)

    #region output variables
    # Set your failure threshold (e.g., 3 or more failed attempts)
    THRESHOLD = 3
    flagged_attempts = detect_failed_login_spikes(alerts, threshold=THRESHOLD)
    user_fail_counts = count_failed_logins_by_user(alerts, threshold=THRESHOLD)
    ip_fail_counts = count_failed_logins_by_ip(alerts, threshold=THRESHOLD)
    multi_user_ips = detect_ips_touching_multiple_users(alerts, min_users=2)
    flagged_breaches = detect_brute_force(alerts, min_failures=3)
    external_attempts = detect_external_ips(alerts)
    priv_escalations = detect_privilege_escalation(alerts)
    suspicious_ips = set()
    for user, ip in flagged_attempts.keys():
        suspicious_ips.add(ip)
    for alert in external_attempts:
        suspicious_ips.add(alert.ip_address)
    for breach in flagged_breaches:
        suspicious_ips.update(breach['fail_ips'])
    total_suspicious_ips = len(suspicious_ips)
    total_flagged_events = (
        len(flagged_attempts) +
        len(flagged_breaches) +
        len(external_attempts) +
        len(priv_escalations)
    )
    #endregion

    #region console output
    print(f"Parsed {len(alerts)} valid Alert objects:")
    print(f"- Successful Logins: {auth_success}")
    print(f"- Failed Logins: {auth_fail}")
    print(f"- Suspicious External IPs: {total_suspicious_ips}")
    print(f"- Privilege Changes: {priv_change}")
    print(f"- Total Flagged Events: {total_flagged_events}")
    print("\n" + "=" * 30)
    print("\n" + "=" * 40)
    print(f"FAILED LOGINS PER USER (>= {THRESHOLD})")
    print("=" * 40)
    if user_fail_counts:
        for user, count in user_fail_counts.items():
            print(f"USER: '{user}' -> {count} failed logins")
    else:
        print("No users exceeded failure threshold.")

    print("\n" + "=" * 40)
    print(f"FAILED LOGINS PER IP (>= {THRESHOLD})")
    print("=" * 40)
    if ip_fail_counts:
        for ip, count in ip_fail_counts.items():
            print(f"IP: '{ip}' -> {count} failed logins")
    else:
        print("No IPs exceeded failure threshold.")

    print("\n" + "=" * 40)
    print("⚠️  IPs TARGETING MULTIPLE USERS (PASSWORD SPRAY)")
    print("=" * 40)
    if multi_user_ips:
        for ip, users in multi_user_ips.items():
            print(f"SUSPICIOUS IP: '{ip}' targeted {len(users)} users: {', '.join(users)}")
    else:
        print("No multi-account IP targeting detected.")
    print(f"SUSPICIOUS ACTIVITY: Failed Logins >= {THRESHOLD}")
    print("=" * 30)
    if flagged_attempts:
        for (user, ip), count in flagged_attempts.items():
            print(f"FLAGGED: User '{user}' from IP '{ip}' failed {count} times.")
    else:
        print("No threshold breaches detected.")
    print("\n" + "=" * 30)
    print("CRITICAL ALERT: Suspicious Successful Logins (3+ Fails Prior)")
    print("=" * 30)
    if flagged_breaches:
        for breach in flagged_breaches:
            print(f"USER: '{breach['username']}'")
            print(f"  - Prior Failures : {breach['fail_count']}")
            print(f"  - Success Time   : {breach['success_time']}")
            print(f"  - Success IP     : {breach['success_ip']}")
            print(f"  - Failed IPs     : {', '.join(breach['fail_ips'])}")
    else:
        print("No suspicious successful logins detected.")
    print("=" * 30 + "\n")
    print(f"EXTERNAL IP ACTIVITY: {len(external_attempts)} attempt(s)")
    print("=" * 30)
    if external_attempts:
        for alert in external_attempts:
            print(f"EXTERNAL: [{alert.alert_type.name}] User '{alert.username}' from Public IP '{alert.ip_address}'")
    else:
        print("No external IP activity detected.")
    print("=" * 30 + "\n")
    print("\n" + "=" * 30)
    print(f"⚡ PRIVILEGE ESCALATION ACTIVITY: {len(priv_escalations)} event(s)")
    print("=" * 30)
    if priv_escalations:
        for alert in priv_escalations:
            print(f"FLAGGED: User '{alert.username}' @ IP '{alert.ip_address}' -> {alert.message}")
    else:
        print("No privilege escalation activity detected.")
    print("=" * 30 + "\n")
    #endregion
    
    #region output summary file
    with open("analysis_summary.txt", "w", encoding="utf-8") as out:
        out.write("====File Analysis Summary=====\n")
        out.write("==============================\n")
        out.write(f"Total alerts: {len(alerts)}\n")
        out.write(f"Total successful logins: {auth_success}\n")
        out.write(f"Total failed logins: {auth_fail}\n")
        out.write(f"Total suspicious IPs: {total_suspicious_ips}\n")
        out.write(f"Total privilege changes: {priv_change}\n")
        out.write(f"Total flagged events: {total_flagged_events}\n")
        out.write("==============================\n")
        #Flagged Repeated Failures
        out.write("Flagged Repeated Failed Logins\n")
        if flagged_attempts:
            for (user, ip), count in flagged_attempts.items():
                out.write(f"WARNING: User '{user}' @ IP '{ip}' -> {count} Failed Logins\n")
        else:
            out.write("No suspicious activity detected.\n")
        out.write("==============================\n")
        # Failed Logins per User
        out.write("=== Failed Logins per Username ===\n")
        if user_fail_counts:
            for user, count in user_fail_counts.items():
                out.write(f"User '{user}' -> {count} Failed Logins\n")
        else:
            out.write("No users exceeded threshold.\n")
        out.write("=================================\n\n")

        # Failed Logins per IP
        out.write("=== Failed Logins per IP Address ===\n")
        if ip_fail_counts:
            for ip, count in ip_fail_counts.items():
                out.write(f"IP '{ip}' -> {count} Failed Logins\n")
        else:
            out.write("No IPs exceeded threshold.\n")
        out.write("====================================\n\n")
        # Multi-User IPs
        out.write("=== IPs Targeting Multiple Accounts ===\n")
        if multi_user_ips:
            for ip, users in multi_user_ips.items():
                out.write(f"IP '{ip}' targeted {len(users)} users: {', '.join(users)}\n")
        else:
            out.write("No multi-account targeting detected.\n")
        out.write("=======================================\n\n")
        #Critical Brute Force
        if flagged_breaches:
            out.write("===CRITICAL: 3+ Failed Logins Followed by Success===\n")
            for breach in flagged_breaches:
                out.write(f"FLAGGED ACCOUNT: {breach['username']}\n")
                out.write(f"  - Failed Attempts : {breach['fail_count']}\n")
                out.write(f"  - Successful Time : {breach['success_time']}\n")
                out.write(f"  - Successful IP   : {breach['success_ip']}\n")
                out.write(f"  - Attacking IPs   : {', '.join(breach['fail_ips'])}\n")
                out.write("-" * 30 + "\n")
        else:
            out.write("No suspicious success patterns detected.\n")        
        out.write("==============================\n")
        # Privilege Escalation Section
        out.write("=== Privilege Escalation / Role Changes ===\n")
        if priv_escalations:
            for alert in priv_escalations:
                out.write(f"WARNING: [{alert.alert_type.name}] User '{alert.username}' @ IP '{alert.ip_address}' -> Message: {alert.message}\n")
        else:
            out.write("No privilege escalation activity detected.\n")
        out.write("================================\n")
        # External IP Section
        out.write("=== External (Public) IP Activity ===\n")
        if external_attempts:
            for alert in external_attempts:
                out.write(f"EXTERNAL ACCESS: [{alert.alert_type.name}] User '{alert.username}' @ IP '{alert.ip_address}' at {alert.date}\n")
        else:
            out.write("No external IP activity detected.\n")
        out.write("=====================================\n\n")    
        # took out the whole list and left it as a true summary
        # out.write("=============Alerts===========\n")
        # out.write("==============================\n")
        # for a in alerts:
        #     out.write(str(a) + "\n")
        # out.write("==============================\n")
        #endregion

    #region suspicious external IPs csv
    csv_filename = "flagged_events.csv"
    export_flagged_events_to_csv(
        csv_filename,
        flagged_attempts,
        flagged_breaches,
        external_attempts,
        priv_escalations
    )
    #endregion

    print("Summary copied to analysis_summary.txt")
    print(f"Suspicious external IPs copied to {csv_filename}")
              

if __name__ == '__main__':
	main()