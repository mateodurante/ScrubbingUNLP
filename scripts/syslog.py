#!/usr/bin/env python
import json
import os
from sys import stdin, stdout
import datetime
import logging
import socket

hostname = socket.gethostname()

logging.basicConfig(filename=f'/var/log/received_exabgp_{hostname}.log', level=logging.INFO)
logger = logging.getLogger(__name__)

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
