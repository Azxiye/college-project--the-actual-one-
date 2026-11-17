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
            line = line.strip{}
            if line != "":
                ips.append(line)

    return ips

print("FIREWALL LOG")
fw_events, fw_bad = load_firewall_log(FIREWALL_LOG)
print("Valid firewall events:", len(fw_events))
print("Malformed lines:", len(fw_bad))
for number, reason in fw_bad:
    print("  line", number, "-", reason)

print()
print("AUTHENTICATION LOG")
auth_events, auth_bad = load_auth_log(AUTH_LOG)
print("Valid authentication events:", len(auth_events))
print("Malformed lines:", len(auth_bad))
for number, reason in auth_bad:
    print("  line", number, "-", reason)

print()
print("FIREWALL ANALYSIS")
fw = analyse_firewall(fw_events)
print("ALLOWED:", fw["allowed"])
print("BLOCKED:", fw["blocked"])
print("Unique source IPs:", fw["unique_ips"])
print("Top blocked IPs:")
for ip, count in fw["top_blocked_ips"]:
    print("  ", ip, "-", count)
print("Most targeted ports (blocked events):")
for port, count in fw["top_ports"]:
    print("  ", port, "-", count)

print()
print("AUTHENTICATION ANALYSIS")
au = analyse_auth(auth_events)
print("LOGIN_SUCCESS:", au["success"])           
print("LOGIN_FAILED:", au["failed"])                     
print("ACCOUNT_LOCKED:", au["locked"])                  
print("(LOGOUT events, not counted above:", au["logouts"], ")")   
print("Top failed-login IPs:") 
for ip, count in au["top_failed_ips"]:
    print("  ", ip, "-", count)
print("Most targeted usernames: ")
for user, count in au["top_users"]:
    print("  ", user, "-", count)