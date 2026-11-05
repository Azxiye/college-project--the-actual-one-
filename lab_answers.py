# Week 3 Lab ================================================
# Task 1 ----------------------------------------------------
# name = "Alex"
# age = 20
# height = 1.75
# likes_coding = True
# print("Name:", name, type(name))
# print("Age:", age, type(age))
# print("Height:", height, type(height))
# print("Likes coding:", likes_coding, type(likes_coding))
 
# age_in_days = age * 365
# print("Approximate age in days:", age_in_days)

# introduction = "Hello, my name is " + name + " and I am " + str(age) + " Years old ."
# print(introduction)

# Task 1 Output 
# Name: Alex <class 'str'>
# Age: 20 <class 'int'>
# Height: 1.75 <class 'float'>
# Likes coding: True <class 'bool'>
# Approximate age in days: 7300
# Hello, my name is Alex and I am 20 Years old .

# Task 2 -----------------------------------------------------
# message = "Python programming is fun"
# print("First 6 characters:", message[:6])
# print("Last 3 characters:", message[-3:])
# print("Reversed", message[::-1])

# Task 2 Output
# First 6 characters: Python
# Last 3 characters: fun
# Reversed nuf si gnimmargorp nohtyP

# Task 3 -----------------------------------------------------
# movies = ["Inception", "The Matrix", "Interstellar", "The Dark Knight"]
# print("Original list:", movies)
# print("First movie:", movies[0])
# print("Last movie:", movies[-1])

# movies.append("The Lord of the Rings")
# print("After appending a movie:", movies)

# movies.insert(1, "The Godfather") # dictionaries counts from 0, then 1, 2, 3, etc
# print("After inserting a movie at index 1:", movies)

# Task 3 Output
# Original list: ['Inception', 'The Matrix', 'Interstellar', 'The Dark Knight']
# First movie: Inception
# Last movie: The Dark Knight
# After appending a movie: ['Inception', 'The Matrix', 'Interstellar', 'The Dark Knight', 'The Lord of the Rings']
# After inserting a movie at index 1: ['Inception', 'The Godfather', 'The Matrix', 'Interstellar', 'The Dark Knight', 'The Lord of the Rings']

# Task 4 -----------------------------------------------------
# student = {
#     "name": "Alex",
#     "student_id": "123456",
#     "Courses": ["Python", "Data Science", "Cybersecurity"],
#     "year": 2,
#     "grades" : [78, 45, 67, 69, 61]
# }

# print("Full student record:", student)
# print("name:", student["name"])
# print("year:", student["year"])
# print("grades:", student["grades"])

# Task 4 Output
# Full student record: {'name': 'Alex', 'student_id': '123456', 'Courses': ['Python', 'Data Science', 'Cybersecurity'], 'year': 2, 'grades': [78, 45, 67, 69, 61]}name: Alex
# year: 2
# grades: [78, 45, 67, 69, 61]

# Task 5 -----------------------------------------------------
# def write_shopping_list():
#     groceries = ["milk" , "eggs", "bread", "butter", "cheese"]
#     with open("shopping_list.txt", "w", encoding="utf-8") as file:
#         for item in groceries:
#             file.write(item + "\n")

# def read_shopping_list():
#     with open("shopping_list.txt", "r", encoding="utf-8") as file:
#         items = file.readlines()
#         for number, item in enumerate(items, start=1):
#             print(str(number) + "." + item.strip())

# write_shopping_list()
# read_shopping_list()

# Task 5 Output 
# 1.milk
# 2.eggs
# 3.bread
# 4.butter
# 5.cheese

# Week 4 Lab ================================================
# Task A1 -----------------------------------------------------
#blocked_count = 0

# with open("Week 4  - Lab Resources/firewall.log", "r", encoding="utf-8") as file:
#     for line in file:
#         if "BLOCKED" in line:
#             blocked_count += 1

# print(f"Total BLOCKED Connections: {blocked_count}")

# Task A1 Output
# Total BLOCKED Connections: 12

# Task A2 -----------------------------------------------------
# import re

# pattern = r"src=(\d{1,3}(?:\.\d{1,3}){3})"
# blocked_ips = []

# with open ("Week 4  - Lab Resources/firewall.log", "r", encoding="utf-8") as file:
#     for line in file:
#         if "BLOCKED" in line:
#             match = re.search(pattern, line)
#             if match:
#                 ip = match.group(1)
#                 if ip not in blocked_ips:
#                     blocked_ips.append(ip)

# print("Unique source IPs from BLOCKED Entries: ")
# for ip in blocked_ips:
#     print(ip)

# Task A2 Output
# Unique source IPs from BLOCKED Entries: 
# 203.0.113.55
# 192.168.1.25
# 198.51.100.23
# 192.168.2.14
# 8.8.8.8
# 192.168.3.7
# 192.168.1.10
# 192.168.2.99
# 198.51.100.77

# Task A3 -----------------------------------------------------
# import re
# private_pattern = r"src=(192\.168\.\d{1,3}\.\d{1,3})"
# blocked_private = 0
# allowed_private = 0

# with open("Week 4  - Lab Resources/firewall.log", "r", encoding="utf-8") as file:
#     for line in file:
#         if re.search(private_pattern, line):
#             if "BLOCKED" in line:
#                 blocked_private += 1
#             elif "ALLOWED" in line:
#                 allowed_private += 1

# print(f"Private 192.168.x.x BLOCKED: {blocked_private}")
# print(f"Private 192.168.x.x ALLOWED: {allowed_private}")

# Task A3 Output
# Private 192.168.x.x BLOCKED: 5
# Private 192.168.x.x ALLOWED: 6

# Task B1 -----------------------------------------------------
# import csv

# total = 0

# with open("Week 4  - Lab Resources/security_incidents.csv", "r", encoding="utf-8") as file:
#     reader = csv.DictReader(file)
#     for row in reader:
#         total += 1

# print(f"Total incidents: {total}")

# Task B1 Output
# Total incidents: 18

# Task B2 -----------------------------------------------------
# import csv
# attack_counts = {}

# with open("Week 4  - Lab Resources/security_incidents.csv", "r", newline="", encoding="utf-8") as file:
#         reader = csv.DictReader(file)
#         for row in reader:
#             attack_type = row["attack_type"]
#         if attack_type not in attack_counts:
#            attack_counts[attack_type] = 0
#         attack_counts[attack_type] += 1

# print("Incidents by attack type: ")
# for attack_type, count in attack_counts.items():
#        print(f"{attack_type}: {count}")

# Task B2 Output
# Incidents by attack type:
# Brute Force: 1

# Task B3 -----------------------------------------------------
# import csv

# ip_counts = {}

# with open("Week 4  - Lab Resources/security_incidents.csv", "r", newline="", encoding="utf-8") as file:
#       reader = csv.DictReader(file)
#       for row in reader:
#             ip = row["source_ip"]
 #            if ip not in ip_counts:
#                   ip_counts[ip] = 0
#             ip_counts[ip] += 1

# top_ip = max(ip_counts, key=ip_counts.get)
# print(f"Source ip with the most incidents: {top_ip} ({ip_counts[top_ip]} incidents)")

# Task B3 Output
# Source ip with the most incidents: 203.0.113.55 (5 incidents)

# Task C2 -----------------------------------------------------
# import json

# with open("Week 4  - Lab Resources/vulnerabilities.json", "r", encoding="utf-8") as file:
#     data = json.load(file)

# print("Critical vulnerabilities: ")
# for item in data["vulnerabilities"]:
#     if item["severity"] == "Critical":
#         print(f'{item["host"]} | {item["vulnerability"]} | CVSS {item["cvss"]}')

# Task C2 Output
# Critical vulnerabilities: 
# web01 | Remote Code Execution in Web Framework | CVSS 9.8
# server01 | Privilege Escalation Vulnerability | CVSS 9.1
# db01 | SQL Service Remote Code Execution | CVSS 9.8
# workstation07 | Browser Sandbox Escape | CVSS 9.6
# vpn01 | VPN Gateway Authentication Bypass | CVSS 9.9

# Task C1 ----------------------------------------------------
# import json

# with open("Week 4  - Lab Resources/vulnerabilities.json", "r", encoding="utf-8") as file:
#       data = json.load(file)

# vulnerabilities = data["vulnerabilities"]
# print(f"total vulnerabilities: {len(vulnerabilities)}")

# Task C1 Output
# total vulnerabilities: 12

# Task C3 ---------------------------------------------------------
import json