import requests
import os
import re
import csv
import json                                 # all these imports are a "just in case" thing, and were from the lecture slides
import socket
import subprocess
import platform        
import hashlib
from datetime import datetime
import sys
import pefile
import winreg
import ipaddress
from pathlib import Path

FOLDER = Path(__file__).parent
FIREWALL_LOG = FOLDER / "firewall.log"
AUTH_LOG = FOLDER / "authentication.log"
SUSPICIOUS_FILE = FOLDER / "suspicious_ips.txt"
OUTPUT_FOLDER = FOLDER / "output"

def get_value(part, name):
    if not part.startswith(name + "="):
        raise ValueError("expected " + name + "=")
    return part[len(name) + 1:]

def parse_firewall_line(line):
    parts = line.split()

    if len(parts) != 8:
        raise ValueError("wrong number of fields")

    action = parts[2]
    if action not in ("ALLOWED", "BLOCKED"):
        raise ValueError("unknown action " + action)

    src = get_value(parts[3], "src")
    dst = get_value(parts[4], "dst")
    port = get_value(parts[6], "port")

    datetime.strptime(parts[0] + " " + parts[1], "%Y-%m-%d %H:%M:%S")

    ipaddress.ip_address(src)
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
        for number, line in enumerate(file, start=1):
            line = line.strip()
            if line =="":
                continue
            try:
                events.append(parse_firewall_line(line))
            except ValueError as error:
                bad_lines.append((number, str(error)))

    return events, bad_lines

AUTH_EVENTS = ("LOGIN_SUCCESS", "LOGIN_FAILED", "ACCOUNT_LOCKED", "LOGOUT")

def parse_auth_line(line):

    parts = line.split()

    if len(parts) != 7:
        raise ValueError("wrong number of fields")

    event = parts[2]
    if event not in AUTH_EVENTS:
        raise ValueError("unknown event " + event)

    user = get_value(parts[3], "user")
    src = get_value(parts[4], "src")
    host = get_value(parts[5], "host")

    datetime.strptime(parts[0] + " " + parts[1], "%Y-%m-%d %H:%M:%S")
    ipaddress.ip_address(src)
    if user == "":
        raise ValueError("username is empty")

    return {
        "time": parts[0] + " " + parts[1],
        "event": event,
        "user": user,
        "src": src,
        "host": host,
    }

def load_auth_log(path):
    """Read the file. Return (good_events, bad_lines)."""
    events = []
    bad_lines = []

    with open(path, "r", encoding="utf-8") as file:
        for number, line in enumerate(file, start=1):
            line = line.strip()
            if line == "":
                continue
            try:
                events.append(parse_auth_line(line))
            except ValueError as error:
                bad_lines.append((number, str(error)))

    return events, bad_lines

TOP_N = 5

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
    all_ips = []
    blocked_ips = []
    blocked_ports = []

    for event in events:
        all_ips.append(event["src"])
        if event["action"] == "ALLOWED":
            allowed += 1
        else:
            blocked += 1
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
    logouts = 0
    failed_ips = []
    failed_users = []

    for event in events:
        if event["event"] == "LOGIN_SUCCESS":
            success += 1
        elif event["event"] == "LOGIN_FAILED": 
            failed += 1
            failed_ips.append(event["src"])
            failed_users.append(event["user"])

        elif event["event"] == "ACCOUNT_LOCKED":
            locked += 1
        else:
            logouts += 1

    return {
        "success": success,
        "failed": failed,
        "locked": locked,
        "logouts": logouts,
        "top_failed_ips": top_n(count_items(failed_ips), TOP_N),
        "top_users": top_n(count_items(failed_users), TOP_N),
    }

BRUTE_FORCE_LIMIT = 10
SUCCESS_AFTER_FAILS = 5
PRIVILEGED_NAMES = ("admin", "root", "administrator")

def load_suspicious_ips(path):
    ips = []
    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if line != "":
                ips.append(line)

    return ips

def find_observations(fw_events, auth_events, suspicious_ips):
    observations = []
    failed_ips = []

    for event in auth_events:
        if event["event"] == "LOGIN_FAILED":
            failed_ips.append(event["src"])
    for ip, count in top_n(count_items(failed_ips), TOP_N):
        if count >= BRUTE_FORCE_LIMIT:
            observations.append(
                ip + " had " + str(count) + "failed logins. That many from one "
                "address looks like automated password guessing, not people making typos."
            )

    fails_in_a_row = {}
    for event in auth_events:
        ip = event["src"]
        if event["event"] == "LOGIN_FAILED":
            fails_in_a_row[ip] = fails_in_a_row.get(ip, 0) + 1
        elif event["event"] == "LOGIN_SUCCESS":
            if fails_in_a_row.get(ip, 0) >= SUCCESS_AFTER_FAILS:
                observations.append(
                    ip + " failed " + str(fails_in_a_row[ip]) + " times and then loggin as '"
                    + event["user"] + "' at " + event["time"] + ". The password might've been guessed, account will be treated as compromised"
                )
            fails_in_a_row[ip] = 0

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
                times_of_day.add(t[11:])
            text = "Account '" + user + "' was locked " + str(len(times)) + " times."
            if len(times_of_day) == 1:
                text += (" Every lockout was at exactly " + list(times_of_day)[0] +
                         ", which suggests a scheduled script, not a person.")

            observations.append(text)

    allowed_ips = []
    for event in fw_events:
        if event["action"] == "ALLOWED":
            allowed_ips.append(event["src"])
    allowed_counts = count_items(allowed_ips)

    success_ips = []
    for event in auth_events:
        if event["event"] == "LOGIN_SUCCESS":
            success_ips.append(event["src"])
    success_counts = count_items(success_ips)

    allowed_text = []
    success_text = []
    for ip in suspicious_ips:
        if allowed_counts.get(ip, 0) > 0:
            allowed_text.append(ip + " (" + str(allowed_counts[ip]) + ")")
        if success_counts.get(ip, 0) > 0:
            success_text.append(ip + " (" + str(success_counts[ip]) + ")")
    if len(allowed_text) > 0:
        observations.append(
             "These suspicious-list IPs logged in successfully: " + ", ".join(success_text)
            + ". A known-bad address with a working login means an account may be compromised."
        )

    failed_total = 0
    failed_privileged = 0
    for event in auth_events:
        if event["event"] == "LOGIN_FAILED":
            failed_total += 1
            if event["user"].lower() in PRIVILEGED_NAMES:
                failed_privileged += 1
    if failed_total > 0 and failed_privileged / failed_total >= 0.3:
        percent = round(100 * failed_privileged / failed_total)
        observations.append(
            str(failed_privileged) + " of " + str(failed_total) + "  failed login (" + str(percent)
            + "%) were against admin, root or administrator. Attackers try these names first "
            "because they exist on almost every system."
        )

    return observations
def add_top_list(lines, title, pairs):
    lines.append(title)
    for number, (item, count) in enumerate(pairs, start=1):
        lines.append(" " + str(number) + ". " + str(item) + " - " +str(count))
    lines.append("")

def make_report_text(fw_events, fw_bad, auth_events, auth_bad, fw, au, observations):
    lines = []
    lines.append("SECURITY INVESTIGATION SUMMARY")
    lines.append("=" * 60)
    lines.append("")

    lines.append("DATA QUALITY")
    lines.append("firewall.log: " + str(len(fw_events)) + " valid " +  str(len(fw_bad)) + " malformed (skipped)")
    for number, reason in fw_bad:
        lines.append(" line " + str(number) + " - " + reason)
    lines.append("authentication.log: " + str(len(auth_events)) + " valid, " + str(len(auth_bad)) + " malformed (skipped)")
    for number, reason in auth_bad:
        lines.append(" line " + str(number) + " - " + reason)
    lines.append("")

    lines.append("FIREWALL ANALYSIS")
    lines.append("Valid Events: " + str(len(fw_events)))
    lines.append("ALLOWED: " + str(fw["allowed"]))
    lines.append("BLOCKED: " + str(fw["blocked"]))
    lines.append("Unique source IPs: " + str(fw["unique_ips"]))
    lines.append("")
    add_top_list(lines, "Top Blocked IPs: ", fw["top_blocked_ips"])
    add_top_list(lines, "Most targeted ports (blocked events):", fw["top_ports"])

    lines.append("AUTHENTICATION ANALYSIS")
    lines.append("Valid events " + str(len(auth_events)))
    lines.append("LOGIN_SUCCESS: " + str(au["success"]))
    lines.append("LOGIN_FAILED: " + str(au["failed"]))
    lines.append("ACCOUNT_LOCKED: " + str(au["locked"]))
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

def save_csv(obvservations, path):
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
        print("ERROR: could not find a log file: ", error.filename)
        print("Put the log files in the same folder as this script.")
        return

    try:
        suspicious_ips = load_suspicious_ips(SUSPICIOUS_FILE)
    except FileNotFoundError:
        print("Warning: suspicious_ips.txt not found, skipping that check.")
        suspicious_ips = []

    fw = analyse_firewall(fw_events)
    au = analyse_auth(auth_events)
    observations = find_observations(fw_events, auth_events, suspicious_ips)

    report_text = make_report_text(fw_events, fw_bad, auth_events, auth_bad, fw, au, observations, print(report_text))

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

    print()
    print("Reports saved in:", OUTPUT_FOLDER)

if __name__ == "__main__":
    main()
    
fw_events, fw_bad = load_firewall_log(FIREWALL_LOG)
auth_events, auth_bad = load_auth_log(AUTH_LOG)
suspicious_ips = load_suspicious_ips(SUSPICIOUS_FILE)

fw = analyse_firewall(fw_events)
au = analyse_auth(auth_events)
observations = find_observations(fw_events, auth_events, suspicious_ips)

report_text = make_report_text(fw_events, fw_bad, auth_events, auth_bad, fw, au, observations)
print(report_text)

OUTPUT_FOLDER.mkdir(exist_ok=True)
save_text(report_text, OUTPUT_FOLDER / "Investigation_summary.txt")
save_json(
    {
        "firewall": fw,
        "authentication": au,
        "observations": observations,
        "malformed_firewall_lines": fw_bad,
        "malformed_auth_lines": auth_bad,
    },
    OUTPUT_FOLDER / "Investigation_summary.json",
)
save_csv(observations, OUTPUT_FOLDER / "observations.csv")
print()
print("Reports saved in :", OUTPUT_FOLDER)