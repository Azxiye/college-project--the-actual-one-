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

events, bad_lines = load_firewall_log(FIREWALL_LOG)
print("Valid firewall events:", len(events))
print("Malformed lines:", len(bad_lines))
for number, reason in bad_lines:
    print("line", number, "-", reason)