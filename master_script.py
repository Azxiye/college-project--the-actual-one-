import requests
import os
import re
import csv
import json
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

BASE_DIR = Path(__file__).parent
FIREWALL_LOG = BASE_DIR / "firewall.log"

FIREWALL_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}\d{2}) "
    r"(?P<action>ALLOWED|BLOCKED) "
    r"src=(?P<src>\S+) dst=(?P<dst>\S+) "
    r"proto=(?P<proto>TCP|UDP) port=(?P<port>\S+) bytes=(?P<bytes>\S+)$"
)

def parse_firewall_line(line):
    """converts one log line into a dictionary, raises ValueError with areason if it's a bad one"""
    match = FIREWALL_PATTERN.match(line)
    if not match:
        raise ValueError("line doesnt match the firewall format")

    fields = match.groupdict()

    try:
        datetime.striptime(fields["timestamp"], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        raise ValueError(f"Invalid timestamp: {fields['timestamp']}")

    for key in ("src", "dst"):
        try:
            ipaddress.ip_ipaddress(fields[key])
        except ValueError:
            raise ValueError(f"invalid {key} IP Address: {fields[key]!r}")

        if not fields["port"].isdigit() or not 0 <= int(fields["port"]) <= 65535:
            raise ValueError(f"invalid port: {fields['bytes']!r}")
        if not fields["bytes"].isdigit():
            raise ValueError(f"invalid byte count: {fields['bytes']!r}")

        fields["port"] = int(fields["port"])
        fields["bytes"] = int(fields["bytes"])
        return fields

def load_firewall_log(path):
    """reads the file and returns (valid_events, malformed_lines)
       bad line is recorded and skipped     
    """
    events = []
    malformed = []

    with open(path, "r", encoding="utf-8") as file:
        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                events.append(parse_firewall_line(line))
            except ValueError as error:
                malformed.append((line_number, str(error),line))

    return events, malformed

if __name__ =="__main__":
    events, malformed = load_firewall_log(FIREWALL_LOG)
    print(f"Valid firewall events: {len(events)}")
    print(f"Malformed lines: {len(malformed)}")
    for line_number, reason, raw in malformed:
        print(f"line {line_number}: {reason}")

# error 1: forgot to add P in port=(?P<port>\S+) line 24
# and forgot to add P in dst=(?P<dst>\S+) line 23