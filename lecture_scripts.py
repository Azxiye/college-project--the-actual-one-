# THESE ARE AI GENERATED FIXES FOR THE CODE BELOW
# lecture 1 code 1
#ip_list = [
#    "192.168.1.10",
#    "10.0.0.5",
#    "172.16.0.8"
#]                 # error, "check" and "save_result" functions are not defined
#
#for ip in ip_list:
#    check(ip)
#    save_result(ip)
#
# lecture 1 code 1 fixed
import platform
import subprocess
from datetime import datetime

ip_list = [
    "192.168.1.10",
    "10.0.0.5",
    "172.16.0.8",
]

results_file = "results.txt"

def check(ip):
    "Returns True if reachable False otherwise."
    count_flag = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.run(["ping", count_flag, "1", ip], capture_output=True, timeout=5)
    except subprocess.TimeoutExpired:
        return "Not reachable"
    except FileNotFoundError:
        return "error: ping not found on this system"

    if result.returncode == 0:
        return "Reachable"
    return "not reachable"

def save_result(ip, status):
    "append one timestamped line to the results file (logging)"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open (results_file, "a") as f:
        f.write(f"{timestamp} - {ip} - {status}\n")

for ip in ip_list:
    status = check(ip) #same check for every ip
    print(f"{ip} is {status}") #show the result
    save_result(ip, status) #keep a record so it can be checked later

# lecture 1 code 2
#for line in logs:         prints every line that has the word "BLOCK"
#    if "BLOCK" in line:
#        print(line)
# lecture 2 code 1
#ip_address = "10.0.0.5" -> found in the log
#status = "BLOCK" -> action recorded by firewall
#count = 4 -> amount of times the event was blocked