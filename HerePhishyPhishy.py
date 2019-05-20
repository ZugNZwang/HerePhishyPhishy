# HerePhishyPhishy
# Eric Holguin
# Mohammad Hossain
# Cyber Infrastructre Defense
# Final Project

from __future__ import print_function, unicode_literals

import sys
import json
import constant
import requests
import urllib.parse
from scapy.all import *
from pprint import pprint
from PyInquirer import prompt
import phishDetector

# Api-endpoint
API_ENDPOINT = "http://checkurl.phishtank.com/checkurl/"

# Logo Print
print(constant.BRAND)

# Menu Print
questions = [
    {
        'type': 'list',
        'name': 'menu',
        'message': 'Select Menu Option:',
        'choices': ['DNS Logging','Check URL','ML Detection',
                    'Auto Check', 'Report', 'Exit'],
        'validate': lambda answer: 'You must choose an option.' \
            if len(answer) == 0 else True
    }
]

# DNS Logging
def querysniff(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            print("\u001b[37m" + str(ip_src) + " -> " + str(ip_dst) + " :\u001b[35m " + "(" +
                    pkt.getlayer(DNS).qd.qname.decode('utf-8') + ")")

# API Check
def phishtankCheck(url):
    post_data = {
        'url': url,
        'format': 'json',
        'app_key': constant.APP_KEY,
    }

    post_data = urllib.parse.urlencode(post_data).encode("utf-8")

    con = urllib.request.urlopen(API_ENDPOINT, data=post_data)
    data = json.loads(con.read())
    con.close()

    if(data['meta']['status'] == 'error'):
        print("\u001b[31:0mError. Make sure full URL is entered.\u001b[0m")
    elif(data['results']['in_database'] == True):
        if(data['results']['valid'] == True):
            print("\u001b[31:0mPhishing URL Detected!\u001b[0m")
        elif(data['results']['valid'] == False):
            print("\u001b[36:0mThis URL seems Safe!\u001b[0m")
    else:
        print("\u001b[31:0mNo results found in database.\u001b[0m")

# Loop Menu
while(1):
    # Get menu choice
    answers = prompt(questions, style=constant.STYLE)

    if(answers.get('menu') == "DNS Logging"):

        try:
            interface = input("Enter Desired Interface: \u001b[37m")

            sniff(iface = interface, filter = 'port 53', prn = querysniff, store=0)
            print("\n \u001b[31:0mClosing Logging...\u001b[0m")

        except KeyboardInterrupt:
            print("User Requested Shutdown")
            print("Exiting...")
            sys.exit(1)

    if(answers.get('menu') == "Check URL"):
        url = input("Enter URL to check: \u001b[37m")
        phishtankCheck(url)

    if(answers.get('menu') == "Auto Check"):
        print("FUTURE")

    if(answers.get('menu') == "ML Detection"):
        url = input("Enter URL to check: \u001b[37m")
        phishDetector.predictURL(url)

    if(answers.get('menu') == "Exit"):
            print("Exiting...")
            sys.exit(1)
