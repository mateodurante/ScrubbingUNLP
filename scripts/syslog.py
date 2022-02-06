#!/usr/bin/env python
import json
import os
from sys import stdin, stdout
# from pymongo import MongoClient
import datetime
import logging

logging.basicConfig(filename='/var/log/received_exabgp.log', level=logging.INFO)
logger = logging.getLogger(__name__)

# ###  DB Setup ###
# client = MongoClient('10.0.4.2', 27017)
# db = client.exabgp_db
# updates = db.bgp_updates

counter = 0
while True:

    line = stdin.readline().strip()
    # When the parent dies we are seeing continual newlines, so we only access so many before stopping
    if line == "":
        counter += 1
        if counter > 100:
            break
        continue
    counter = 0

    # updates.insert({"data": line}, check_keys=False)
    logging.info(line)
