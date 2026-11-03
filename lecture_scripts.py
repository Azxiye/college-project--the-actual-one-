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

# lecture 1 code 2
#for line in logs:         prints every line that has the word "BLOCK"
#    if "BLOCK" in line:
#        print(line)
# lecture 2 code 1
#ip_address = "10.0.0.5" -> found in the log
#status = "BLOCK" -> action recorded by firewall
#count = 4 -> amount of times the event was blocked
# lecture 2 code 2
#line = "10:03 BLOCK 10.0.0.5"
#
#time = line[0:5]
#action = line[6:11]
#ip = line[12:]         works without bugs
#
#print(time, action, ip)
# lecture 2 code 3
ip = "10.0.0.5"
count = 3
message = f"IP {ip} was blocked {count} times"
print(message)