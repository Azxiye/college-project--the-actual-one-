# Security Log Investigation
This is the actual repository for the project,
the main script is 'master_script.py'. The outputs of the script will be created when you run the script once.

# What does the script do?
This script is to scan the logs and make a comprehensible output for the user and Analyst to read and understand.
It scans the authentication.log and firewall.log, then put into sections like Data Quality, Firewall Analysis, Blocked IPs, Most Targeted Ports, Authentication Analysis, Top failed login IPs, Targeted usernames,
and Security Observations. 

# How do I use this?
- Download the latest release
- Extract the ZIP file to anywhere
- Open the folder in PowerShell
    - Open the folder in file explorer first, then type into the directory bar "powershell" and press enter.
    - Lastly, type "python master_script.py"
- Output will be printed

# Requirements
AT LEAST Python v3.14

# Expected Output
## Data Quality
in firewall.log, it should list the malformed data, which is skipped.
in authentication.log, it should also list malformed data, which is skipped.

## Firewall Analysis
Lists the Valid Events, ALLOWED and BLOCKED IPs, and Unique Source IPs.

## Top Blocked IPs
Lists how many times a specific IP has been blocked, from most to least.

## Most Targeted Ports
Lists how many times a port has been targeted.

## Authentication Analysis
Lists Valid Events, Failed and Successful Logins, Account locks, and Logout events.

## Top failed-login IPs
Lists the amount of times IPs failed to login.

## Most Targeted usernames
In a ranking list, it shows which username was attacked the most.

## Security Observations
Lists the things that should be investigated.