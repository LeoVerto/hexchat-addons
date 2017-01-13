#!/usr/bin/python
# -*- coding: utf-8 -*-

__module_name__ = "Reverse WHOIS"
__module_version__ = "1.0"
__module_description__ = "Find user by hostname or IP."

import hexchat
import re

hexchat.emit_print("Generic Message", "Loading", "{} {} - {}".format(
                   __module_name__, __module_version__,
                   __module_description__))


def ip_to_hex(ip):
    oc = [int(n) for n in ip.split(".")]
    result = oc[3] + (oc[2] * 256) + (oc[1] * 256**2) + (oc[0] * 256**3)
    return hex(result)[2:]


def find_hostname(hostname, cont=None, complete_match=True):
    if not cont:
        cont = hexchat.get_context();

    users = cont.get_list("users")
    for user in users:
        host = user.host.split("@")[1].lower()
        if hostname in host:
            if complete_match and not host == hostname:
                break
            
            return user.nick
    return None


def find_hostname_cmdhandler(word, word_eol, userdata):
    if len(word) < 2:
        print("Second arg must be the hostname!")
    else:
        hostname = word[1]
       
        user = find_hostname(hostname)
        
        if user:
            print("User {} has hostname {}.".format(user, hostname))
        else:
            print("Found no user with hostname {}.".format(hostname))
        
    return hexchat.EAT_ALL


def find_ip_cmdhandler(word, word_eol, userdata):
    if len(word) < 2:
        print("Second arg must be the IPv4 address!")
    else:
        regex = re.search(r"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)", word[1])
        if regex:
            ipv4 = regex.group()
            user = find_hostname(ipv4, complete_match=False)
            
            # Secondary detection: IP with hyphens instead of spaces
            if not user:
                user = find_hostname(ipv4.replace(".", "-"), complete_match=False)
                # Tertiary detection: Hex IP addresses
                if not user:
                    user = find_hostname(ip_to_hex(ipv4), complete_match=False)
                
            if user:
                print("User {} has IP address {}.".format(user, ipv4))
            else:
                print("Found no user with IP address {}".format(ipv4))
        else:
            print("{} is not a valid IPv4 address!".format(word[1]))
                
    return hexchat.EAT_ALL

hexchat.hook_command("FINDHOSTNAME", find_hostname_cmdhandler, help="/FINDHOSTNAME <hostname> Find user by hostname.")
hexchat.hook_command("FINDIP", find_ip_cmdhandler, help="/FINDIP <ip> Find user by IPv4 address.")
