import os
import re
import csv
import json                                 
import socket
import subprocess
import platform        
import hashlib
from datetime import datetime
import ipaddress
from pathlib import Path

# Loading and Checking the firewall.log file ============================================================================
FOLDER = Path(__file__).parent
FIREWALL_LOG = FOLDER / "firewall.log"                  # directory for the specific file if variable is called  
AUTH_LOG = FOLDER / "authentication.log"                # directory for the specific file if variable is called
SUSPICIOUS_FILE = FOLDER / "suspicious_ips.txt"         # directory for the specific file if variable is called
OUTPUT_FOLDER = FOLDER / "output"                       # files "firewall.log" "authentication.log" and "suspicious_ips.txt" will output here inside a folder

def get_value(part, name):
    if not part.startswith(name + "="):
        raise ValueError("expected " + name + "=")
    return part[len(name) + 1:]

def parse_firewall_line(line):
    parts = line.split()

    # a good line will have 8 parts:
    # date, time, ACTION, src=, dst=, proto=, port= bytes=
    # anything less or more than 8 parts will count as a malformed line
    if len(parts) != 8:
        raise ValueError("wrong number of fields")

    action = parts[2]
    if action not in ("ALLOWED", "BLOCKED"):
        raise ValueError("unknown action " + action)

    src = get_value(parts[3], "src")
    dst = get_value(parts[4], "dst")
    port = get_value(parts[6], "port")

    # checking if the value is real
    datetime.strptime(parts[0] + " " + parts[1], "%Y-%m-%d %H:%M:%S") # raises ValueError if date/time is a malformed one

    ipaddress.ip_address(src) # the one raising if it's not a real IP
    ipaddress.ip_address(dst)
    if not port.isdigit():
        raise ValueError("port is not a number")

    return {
        "time": parts[0] + " " + parts[1],
        "action": action,
        "src": src,
        "dst": dst,
        "port": int(port),
    }

def load_firewall_log(path):
    events = []
    bad_lines = []

    with open(path, "r", encoding="utf-8") as file:
        for number, line in enumerate(file, start=1): # reads the lines in the logs one at a time
            line = line.strip()
            if line =="": # skips empty lines
                continue
            try:
                events.append(parse_firewall_line(line))
            except ValueError as error:
                bad_lines.append((number, str(error))) # remembers and continues

    return events, bad_lines

# loading and checking the authentication.log file ============================================================================
# however logout events will not be counted in the statistics later on
AUTH_EVENTS = ("LOGIN_SUCCESS", "LOGIN_FAILED", "ACCOUNT_LOCKED", "LOGOUT")

def parse_auth_line(line):

    parts = line.split()

    # authentication.log has 7 part
    # date, time, EVENT, user=, src=, host=, method=
    if len(parts) != 7: 
        raise ValueError("wrong number of fields") # raises error if the line DOES NOT HAVE 7 parts

    event = parts[2]
    if event not in AUTH_EVENTS:                        # Raises error if the "event" is not listed in
        raise ValueError("unknown event " + event)      # "AUTH_EVENTS"

    user = get_value(parts[3], "user")
    src = get_value(parts[4], "src")
    host = get_value(parts[5], "host")

    datetime.strptime(parts[0] + " " + parts[1], "%Y-%m-%d %H:%M:%S") # checking if the values are real
    ipaddress.ip_address(src)
    if user == "":                                   # Raises error if the username is empty
        raise ValueError("username is empty")           

    return {
        "time": parts[0] + " " + parts[1],
        "event": event,                         # gives back one line as a dictionary
        "user": user,                           # only works if the checks above this passed
        "src": src,
        "host": host,
    }

def load_auth_log(path):
    # Reads the file and Returns (good_events, bad_lines).
    events = []
    bad_lines = []

    with open(path, "r", encoding="utf-8") as file:
        for number, line in enumerate(file, start=1): # reads the file one line at a time
            line = line.strip()
            if line == "": # skips empty lines
                continue
            try:
                events.append(parse_auth_line(line))
            except ValueError as error:
                bad_lines.append((number, str(error))) # remembers the bad line and continues

    return events, bad_lines

# analysing firewall data from firewall.log ============================================================================
TOP_N = 5 # shows 5 outputs, changing it to 10 shows 10 outputs, etc

def count_items(items):
    counts = {}
    for item in items:
        counts[item] = counts.get(item, 0) + 1
    return counts

def top_n(counts, n):
    pairs = list(counts.items())
    pairs.sort(key=lambda pair: pair[1], reverse=True)
    return pairs[:n]

def analyse_firewall(events):
    allowed = 0
    blocked = 0
    all_ips = []                   # statistics and dictionaries to store scanned data for firewall
    blocked_ips = []
    blocked_ports = []

    for event in events:
        all_ips.append(event["src"])
        if event["action"] == "ALLOWED":
            allowed += 1                                    # adds 1 to the "allowed" variable if the line EXACTLY has "ALLOWED" in the line
        else:
            blocked += 1                                    # adds 1 to the "blocked" variable if the line EXACTLY DOES NOT have "ALLOWED" in the line
            blocked_ips.append(event["src"])
            blocked_ports.append(event["port"])

    return {
        "allowed": allowed,
        "blocked": blocked,
        "unique_ips": len(set(all_ips)),
        "top_blocked_ips": top_n(count_items(blocked_ips), TOP_N),
        "top_ports": top_n(count_items(blocked_ports), TOP_N),
    }

def analyse_auth(events):
    success = 0
    failed = 0
    locked = 0
    logouts = 0                             # statistics and dictionaries to store scanned data for authentication
    failed_ips = []
    failed_users = []

    for event in events:
        if event["event"] == "LOGIN_SUCCESS":
            success += 1                                    # adds 1 to the "success" variable if line EXACTLY has "LOGIN_SUCCESS" in the line
        elif event["event"] == "LOGIN_FAILED": 
            failed += 1                                     # adds 1 to the "failed" variable if line EXACTLY DOES NOT have "LOGIN_SUCCESS" in the line
            failed_ips.append(event["src"])
            failed_users.append(event["user"])

        elif event["event"] == "ACCOUNT_LOCKED":
            locked += 1                 # adds 1 to the "locked" variable if the line EXACTLY has "ACCOUNT_LOCKED"
        else:
            logouts += 1                # adds 1 to the "logouts" variable if the line EXACTLY has "LOGOUT"

    return {
        "success": success,
        "failed": failed,
        "locked": locked,
        "logouts": logouts,
        "top_failed_ips": top_n(count_items(failed_ips), TOP_N),
        "top_users": top_n(count_items(failed_users), TOP_N),
    }

# security observations
BRUTE_FORCE_LIMIT = 10                                          # if there is an 11th attempt, it will be added to the observation statistics.
SUCCESS_AFTER_FAILS = 5                                         # if 5 login fails and 6th attempt is a success, it will be added to the observation statistics.
PRIVILEGED_NAMES = ("admin", "root", "administrator")           # common names hijackers will try to take control

def load_suspicious_ips(path):
    ips = []
    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if line != "": # skips empty lines
                ips.append(line)

    return ips

def find_observations(fw_events, auth_events, suspicious_ips):
    observations = []
    failed_ips = [] # failed logins from one IP by password guessing

    for event in auth_events:
        if event["event"] == "LOGIN_FAILED":
            failed_ips.append(event["src"])
    for ip, count in top_n(count_items(failed_ips), TOP_N):
        if count >= BRUTE_FORCE_LIMIT:
            observations.append(                                #
                ip + " had " + str(count) + " failed logins. That many from one "
                "address looks like automated password guessing, not people making typos.")

    # a successful login after several failures (account compromised alert)
    # this part reads from oldest to newest, top to bottom
    fails_in_a_row = {}
    for event in auth_events:
        ip = event["src"]
        if event["event"] == "LOGIN_FAILED":
            fails_in_a_row[ip] = fails_in_a_row.get(ip, 0) + 1
        elif event["event"] == "LOGIN_SUCCESS":
            if fails_in_a_row.get(ip, 0) >= SUCCESS_AFTER_FAILS:
                observations.append(
                    ip + " failed " + str(fails_in_a_row[ip]) + " times and then logged in as '"
                    + event["user"] + "' at " + event["time"] + ". The password might've been guessed, account will be treated as compromised"
                )
            fails_in_a_row[ip] = 0 # success ends the run of failures
     # the same account locked out again and again
    lock_times = {}
    for event in auth_events:
        if event["event"] == "ACCOUNT_LOCKED":
            user = event["user"]
            if user not in lock_times:
                lock_times[user] = []
            lock_times[user].append(event["time"])
    for user in lock_times:
        times = lock_times[user]
        if len(times) >= 2:
            times_of_day = set()
            for t in times:
                times_of_day.add(t[11:]) # keeps the HH:MM:SS part
            text = "Account '" + user + "' was locked " + str(len(times)) + " times."
            if len(times_of_day) == 1:
                text += (" Every lockout was at exactly " + list(times_of_day)[0] +
                         ", which suggests a scheduled script, not a person.")

            observations.append(text)
    # suspicious IPs that may or may not have been allowed by the firewall and them logging in
    allowed_ips = []
    for event in fw_events:
        if event["action"] == "ALLOWED":
            allowed_ips.append(event["src"])
    allowed_counts = count_items(allowed_ips)

    # IPs that had a successful login attempt
    success_ips = []
    for event in auth_events:
        if event["event"] == "LOGIN_SUCCESS": # adds every line with exactly "LOGIN_SUCCESS" to the
            success_ips.append(event["src"])  # success_ips dictionary list
    success_counts = count_items(success_ips)

    allowed_text = []
    success_text = []
    for ip in suspicious_ips:
        if allowed_counts.get(ip, 0) > 0: # ips that were allowed by the firewall
            allowed_text.append(ip + " (" + str(allowed_counts[ip]) + ")")
        if success_counts.get(ip, 0) > 0: # ips that had a successful login
            success_text.append(ip + " (" + str(success_counts[ip]) + ")")

    if len(success_text) > 0: # only does the following IF success_text has something
        observations.append(
        "These suspicious-list IPs logged in successfully: " + ", ".join(success_text)
        + ". A known-bad address with a working login means an account may be compromised."
    )
    if len(allowed_text) > 0: # only does the following IF allowed_text has something
        observations.append(
            "These suspicious-list IPs were ALLOWED through the firewall: " + ", ".join(allowed_text)
            + ". Traffic from a known-bad address should normally be blocked."
        )
    # attacks against admin usernames
    failed_total = 0
    failed_privileged = 0
    for event in auth_events:
        if event["event"] == "LOGIN_FAILED":
            failed_total += 1
            if event["user"].lower() in PRIVILEGED_NAMES:
                failed_privileged += 1 # adds 1 count to the "failed_privileged" variable if there's a failed login attempt on the "admin", "adminstrator", or "root" usernames
    if failed_total > 0 and failed_privileged / failed_total >= 0.3:
        percent = round(100 * failed_privileged / failed_total)
        observations.append(
            str(failed_privileged) + " of " + str(failed_total) + "  failed logins (" + str(percent)
            + "%) were against admin, root or administrator. Attackers try these names first "
            "because they exist on almost every system."
        )

    return observations
# building and saving the report =============================================================================================
def add_top_list(lines, title, pairs):
    lines.append(title)
    for number, (item, count) in enumerate(pairs, start=1):
        lines.append(" " + str(number) + ". " + str(item) + " - " +str(count))
    lines.append("")

def make_report_text(fw_events, fw_bad, auth_events, auth_bad, fw, au, observations):
    lines = []
    lines.append("SECURITY INVESTIGATION SUMMARY")
    lines.append("=" * 60)                                                                 # easy to read output
    lines.append("")

    lines.append("DATA QUALITY") # skips malformed lines in "firewall.log" if there's < 8 > variables in the line.
    lines.append("firewall.log: " + str(len(fw_events)) + " valid, " +  str(len(fw_bad)) + " malformed (skipped)")                   # easy to read output
    for number, reason in fw_bad:
        lines.append(" line " + str(number) + " - " + reason)
    lines.append("authentication.log: " + str(len(auth_events)) + " valid, " + str(len(auth_bad)) + " malformed (skipped)")
    for number, reason in auth_bad:
        lines.append(" line " + str(number) + " - " + reason)
    lines.append("")

    lines.append("FIREWALL ANALYSIS")
    lines.append("Valid Events: " + str(len(fw_events)))
    lines.append("ALLOWED: " + str(fw["allowed"]))
    lines.append("BLOCKED: " + str(fw["blocked"]))                                     # easy to read output
    lines.append("Unique source IPs: " + str(fw["unique_ips"]))
    lines.append("")
    add_top_list(lines, "Top Blocked IPs:", fw["top_blocked_ips"])
    add_top_list(lines, "Most targeted ports (blocked events):", fw["top_ports"])

    lines.append("AUTHENTICATION ANALYSIS")
    lines.append("Valid events: " + str(len(auth_events)))
    lines.append("LOGIN_SUCCESS: " + str(au["success"]))
    lines.append("LOGIN_FAILED: " + str(au["failed"]))
    lines.append("ACCOUNT_LOCKED: " + str(au["locked"]))                               # easy to read output
    lines.append("(LOGOUT events, excluded above: " + str(au["logouts"]) + ")")
    lines.append("")
    add_top_list(lines, "Top failed-login IPs: ", au["top_failed_ips"])
    add_top_list(lines, "Most targeted usernames:", au["top_users"])

    lines.append("SECURITY OBSERVATIONS")
    for number, text in enumerate(observations, start=1):
        lines.append(str(number) + ". " + text)
        lines.append("")

    lines.append("Note: these are indicators to investigate, not proof of an attack.")
    return "\n".join(lines)

def save_text(text, path):
    with open(path, "w", encoding="utf-8") as file:
        file.write(text + "\n")

def save_json(data, path):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)

def save_csv(observations, path):
    with open(path, "w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["number", "observation"])
        for number, text in enumerate(observations, start=1):
            writer.writerow([number, text])

def main():
    try:
        fw_events, fw_bad = load_firewall_log(FIREWALL_LOG)
        auth_events, auth_bad = load_auth_log(AUTH_LOG)
    except FileNotFoundError as error:
        print("ERROR: could not find a log file: ", error.filename) # prints when a log file is not found
        print("Put the log files in the same folder as this script.")
        return

    try:
        suspicious_ips = load_suspicious_ips(SUSPICIOUS_FILE)
    except FileNotFoundError:
        print("Warning: suspicious_ips.txt not found, skipping that check.") # prints when "suspicious_ips.txt" is not found
        suspicious_ips = []

    fw = analyse_firewall(fw_events)
    au = analyse_auth(auth_events)
    observations = find_observations(fw_events, auth_events, suspicious_ips)

    report_text = make_report_text(fw_events, fw_bad, auth_events, auth_bad, fw, au, observations)
    print(report_text)

    try:
        OUTPUT_FOLDER.mkdir(exist_ok=True)
        save_text(report_text, OUTPUT_FOLDER / "investigation_summary.txt")
        save_json(
            {
                "firewall": fw,
                "authentication": au,
                "observations": observations,
                "malformed_firewall_lines": fw_bad,
                "malformed_auth_lines": auth_bad,
            },
            OUTPUT_FOLDER / "investigation_summary.json", 
        )
        save_csv(observations, OUTPUT_FOLDER / "observations.csv")
    except OSError as error:
        print("ERROR: could not save the reports:", error)
        return

    print()                     # blank print for a cleaner output 
    print("Reports saved in:", OUTPUT_FOLDER)

if __name__ == "__main__":
    main()

