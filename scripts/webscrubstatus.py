from flask import request
import requests
from sys import stdout
import logging
import socket
import json
import time
from sys import stdin, stdout
import base64
import subprocess
# from pathlib import Path
import os

hostname = socket.gethostname()

logging.basicConfig(filename=f'/var/log/webscrubstatus_{hostname}.log', level=logging.INFO)
logger = logging.getLogger(__name__)


##### WEBSCRUB URL #####
webscrub_url = None

logger.info('Intentando levantar config URL API del WebScrub')

while not webscrub_url:
    # TODO: ver como configuramos esto...
    try:
        with open('/etc/webscrub.txt') as f:
            webscrub_url = f.read().strip()
    except:
        pass

    # esperamos a tener la url del webscrub
    time.sleep(1)

logger.info('URL recibida: ' + webscrub_url)

while True:
    # test if url is reachable
    try:
        response = requests.get(webscrub_url)
        break
    except:
        logger.error('No se pudo conectar con el WebScrub, reintentando en 5 segundos')
        time.sleep(5)

logger.info('URL funciona: ' + webscrub_url)
##### END WEBSCRUB URL #####

def run_cmd(cmd):
    cmd = cmd.split()
    logger.info(' '.join(cmd))
    s = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return base64.b64encode(s.stdout).decode('utf-8'), base64.b64encode(s.stderr).decode('utf-8'), s.returncode

def get_cmd_data(cmd):
    res = run_cmd(cmd)
    result = {'stdout': res[0], 'stderr': res[1], 'returncode': res[2]}
    return {'cmd': cmd, 'hostname':hostname, 'result': result, 'time': time.time()}
    # requests.post(f'{webscrub_url}peermessage/nodestatus', data=json.dumps({'cmd': cmd, 'hostname':hostname, 'result': result, 'time': time.time()}))

def flatten_nested(flatten, sep='/'):
    nested = {}
    for key, value in flatten.items():
        components = key.split(sep)
        subtarget = nested
        for component in components[:-1]:
            subtarget = subtarget.setdefault(component, dict())
        subtarget[components[-1]] = value
    return nested

def if_states():
    data = []
    base='/sys/class/net/'
    for iface in os.listdir(base):
        iface_path = os.path.join(base, iface)
        iface_data = {}
        for root, dirs, files in os.walk(iface_path):
            rel_path = root[len(iface_path)+1:]
            for f in files:
                file_path = os.path.join(rel_path, f)
                fr = os.path.join(root, f)
                try:
                    with open(fr, 'r') as fd:
                        iface_data[file_path] = fd.read().strip()
                except:
                    pass
        # To nested dict
        data.append({'hostname': hostname, 'time': time.time(), 'name': iface, 'data': flatten_nested(iface_data)})
    return data

cmds = [
    'ip -o address ls',
    'ip -o link ls',
    'ip -o tun ls',
    'ip -o route ls',
    'iptables -nvxL',
]

while True:
    res_cmds = []
    for cmd in cmds:
        res_cmds.append(get_cmd_data(cmd))
    
    res_ifaces = if_states()
    
    requests.post(f'{webscrub_url}peermessage/nodestatus', data=json.dumps({'cmds':res_cmds, 'ifaces': res_ifaces}))
    
    time.sleep(10)
