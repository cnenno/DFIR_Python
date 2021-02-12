
## Speed Snort Rules
## this is a simple starter script to write snort rules
## based off previous rules and new ips and domains

#!/bin/python3

rules_file = open("/tmp/ioc.rules", "a+")
ips = open("/tmp/iocips.txt", "r")
domains = open("/tmp/iocdomains.txt", "r")
sid = 1000010

for ip in ips:
    rule_str = "alert ip " + ip.strip() + " any -> any any (msg:\"Known Bad Traffic\"; sid: " + str(sid) + ";)\n"
    rules_file.write(rule_str)
    sid += 1

def get_len(length):
    if length < 10:
        return "0" + str(length)
    else:
        return length

for domain in domains:
    d = domain.strip().split(".")
    domain_name = ""
    for x in d:
        if x != "":
            domain_name += "|" + get_len(len(x)) + "|" + x
    domain_name += "|00|"
    print(domain_name)
    rule_str = "alert udp any any -> any any (msg:\"DNS Request for " + domain_name + "\"; content: \"" + domain_name + "\"; sid: " + str(sid) + ";)\n"
    rules_file.write(rule_str)
    sid += 1

rules_file.close()
