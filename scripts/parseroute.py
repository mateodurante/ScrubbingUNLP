#!/usr/bin/env python
import json
import os
from sys import stdin, stdout
import datetime
import requests

counter = 0
peer = {}
red = {}

while True:

    line = stdin.readline().strip()

    # When the parent dies we are seeing continual newlines, so we only access so many before       #stopping
    if line == "":
        counter += 1
        if counter > 100:
            break
        continue
    counter = 0

    message = json.loads(line)

    if message["type"] == "update":
        try:
            update_hash = message['neighbor']['message']['update']
            if 'announce' in update_hash.keys():
                peer = message['neighbor']['address']['peer']
                array  = message['neighbor']['message']['update']['announce']['ipv4 unicast'][peer]
                action = "add"
                message_type = "announce"
                asn = update_hash['attribute']['as-path'][0]
            elif 'withdraw' in update_hash.keys():
                array  = message['neighbor']['message']['update']['withdraw']['ipv4 unicast']
                action = "del"
                message_type = "withdraw"
                asn=""

            net = array[0]['nlri']

            if message_type == "announce":
                value = "{0} route {1} next-hop self origin igp as-path [{2}]".format(message_type, net, asn)
            elif message_type == "withdraw":
                value = "{0} route {1}".format(message_type, net)

            # Announce received ExaBGP-route trough Quagga peering
            if (net):
                # Pagina para la sintaxis: https://thepacketgeek.com/advanced-router-peering-and-route-announcement/
                post = requests.post('http://localhost:5000/', data = {'command' : value})
                out = os.system("ip route {0} {1} dev {2}".format(action, net, asn))

        except KeyError as detail:
            pass

