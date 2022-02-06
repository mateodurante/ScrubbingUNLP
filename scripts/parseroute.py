#!/usr/bin/env python
import json
import os
from sys import stdin, stdout
import datetime
import requests
import logging
import socket
import subprocess

hostname = socket.gethostname()

logging.basicConfig(filename=f'/var/log/parseroute_{hostname}.log', level=logging.INFO)
logger = logging.getLogger(__name__)

counter = 0
peer = {}
red = {}

def existe_tunel(asn_remote):
    s = subprocess.run(['ip','link','ls', str(asn_remote)], stdout=subprocess.PIPE)
    return s.returncode == 0

def existe_rutas(asn_remote):
    s = subprocess.run(['ip','route','ls','dev',str(asn_remote)], stdout=subprocess.PIPE)
    return s.stdout.decode('utf-8') != ''

def extraer_asn_de_ruta(net):
    s = subprocess.run(['ip','route','ls',str(net)], stdout=subprocess.PIPE)
    if s.returncode == 0:
        try:
            return s.stdout.decode('utf-8').split('\n')[0].split(' ')[2]
        except:
            return None


def create_gre(peer, local, asn_remote):
    # checkear si existe el tunel
    if not existe_tunel(asn_remote):
        # si no existe, crearlo
        s = subprocess.run(['ip','tunnel','add',str(asn_remote),'mode','gre','remote',str(peer),'local',str(local),'ttl','255'], stdout=subprocess.PIPE)
    s = subprocess.run(['ip','link','set',str(asn_remote),'up'], stdout=subprocess.PIPE)
    return s.returncode

def remove_gre(asn_remote):
    # checkear si existe el tunel y no tiene rutas
    if existe_tunel(asn_remote) and not existe_rutas(asn_remote):
        # eliminarlo
        s = subprocess.run(['ip','tunnel','del',str(asn_remote)], stdout=subprocess.PIPE)

def aplicar_ruta(value, action, net, asn_remote):
    # Pagina para la sintaxis: https://thepacketgeek.com/advanced-router-peering-and-route-announcement/
    # Announce received ExaBGP-route trough Quagga peering
    post = requests.post('http://localhost:5000/', data = {'command' : value})
    # Apply local route to the remote AS
    if asn_remote:
        cmd = f"ip route {action} {net} dev {asn_remote}"
        logger.info(cmd)
        out = os.system(cmd)
    else:
        logger.info(f'No se pudo encontrar el ASN del peer {peer} en las rutas, por lo que se ignorara eliminar la ruta')

def remove_orphan_gre():
    # eliminar tuneles sin rutas
    s = subprocess.run(['ip','tunnel','ls'], stdout=subprocess.PIPE)
    if s.returncode == 0:
        for line in s.stdout.decode('utf-8').split('\n'):
            try:
                asn = int(line.split(':')[0])
                if not existe_rutas(asn):
                    remove_gre(asn)
            except:
                continue

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
            neighbor = message['neighbor']
            update = neighbor['message']['update']
            if 'announce' in update.keys():
                peer = neighbor['address']['peer']
                local = neighbor["address"]["local"]
                array  = update['announce']['ipv4 unicast'][peer]
                net = array[0]['nlri']
                message_type = "announce"
                action = "add"
                asn_remote = update['attribute']['as-path'][0]
                create_gre(peer, local, asn_remote)
                value = f"announce route {net} next-hop self origin igp as-path [{asn_remote}]"
                aplicar_ruta(value, action, net, asn_remote)
            elif 'withdraw' in update.keys():
                array  = update['withdraw']['ipv4 unicast']
                net = array[0]['nlri']
                action = "del"
                message_type = "withdraw"
                asn_remote = extraer_asn_de_ruta(net)
                value = f"withdraw route {net}"
                aplicar_ruta(value, action, net, asn_remote)
                if asn_remote:
                    remove_gre(asn_remote)
                remove_orphan_gre()

            

        except KeyError as detail:
            pass

