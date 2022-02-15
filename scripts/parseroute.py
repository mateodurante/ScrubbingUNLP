#!/usr/bin/env python
import json
import os
from sys import stdin, stdout
import datetime
import requests
import logging
import socket
import subprocess
import time

hostname = socket.gethostname()

logging.basicConfig(filename=f'/var/log/parseroute_{hostname}.log', level=logging.INFO)
logger = logging.getLogger(__name__)

counter = 0
peer = {}
red = {}

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


def existe_tunel(asn_remote):
    cmd = ['ip','link','ls', str(asn_remote)]
    logger.info(' '.join(cmd))
    s = subprocess.run(cmd, stdout=subprocess.PIPE)
    return s.returncode == 0

def existe_rutas(asn_remote):
    cmd = ['ip','route','ls','dev',str(asn_remote)]
    logger.info(' '.join(cmd))
    s = subprocess.run(cmd, stdout=subprocess.PIPE)
    return s.stdout.decode('utf-8') != ''

def extraer_asn_de_ruta(net):
    cmd = ['ip','route','ls',str(net)]
    logger.info(' '.join(cmd))
    s = subprocess.run(cmd, stdout=subprocess.PIPE)
    if s.returncode == 0:
        try:
            return s.stdout.decode('utf-8').split('\n')[0].split(' ')[2]
        except:
            return None


def create_or_up_gre(local, asn_remote):
    # checkear si existe el tunel
    if not existe_tunel(asn_remote):
        # si no existe, crearlo
        peer = get_tunnel_ip(asn_remote)
        cmd = ['ip','tunnel','add',str(asn_remote),'mode','gre','remote',str(peer),'local',str(local),'ttl','255']
        logger.info(' '.join(cmd))
        s = subprocess.run(cmd, stdout=subprocess.PIPE)
    cmd = ['ip','link','set',str(asn_remote),'up']
    logger.info(' '.join(cmd))
    s = subprocess.run(cmd, stdout=subprocess.PIPE)
    return s.returncode

def remove_gre(asn_remote, force=False):
    # checkear si existe el tunel y no tiene rutas
    if force or (existe_tunel(asn_remote) and not existe_rutas(asn_remote)):
        # eliminarlo
        cmd = ['ip','tunnel','del',str(asn_remote)]
        logger.info(' '.join(cmd))
        s = subprocess.run(cmd, stdout=subprocess.PIPE)

def down_gre(asn_remote):
    # checkear si existe el tunel y no tiene rutas
    if existe_tunel(asn_remote) and not existe_rutas(asn_remote):
        # bajarlo
        cmd = ['ip','link','set',str(asn_remote),'down']
        logger.info(' '.join(cmd))
        s = subprocess.run(cmd, stdout=subprocess.PIPE)

def send_cmd(cmd):
    # Pagina para la sintaxis: https://thepacketgeek.com/advanced-router-peering-and-route-announcement/
    # Announce received ExaBGP-route trough Quagga peering
    return requests.post('http://localhost:5000/', data = {'command' : cmd})

def aplicar_ruta(value, action, net, asn_remote):
    send_cmd(value)
    # Apply local route to the remote AS
    if asn_remote:
        cmd = f"ip route {action} {net} dev {asn_remote}"
        logger.info(cmd)
        out = os.system(cmd)
    else:
        logger.info(f'No se pudo encontrar el ASN del peer {peer} en las rutas, por lo que se ignorara eliminar la ruta')

def remove_orphan_gre():
    # eliminar tuneles sin rutas
    cmd = ['ip','tunnel','ls']
    logger.info(' '.join(cmd))
    s = subprocess.run(cmd, stdout=subprocess.PIPE)
    if s.returncode == 0:
        for line in s.stdout.decode('utf-8').split('\n'):
            try:
                asn = int(line.split(':')[0])
                if not existe_rutas(asn):
                    remove_gre(asn)
            except:
                continue

def get_tunnel_ip(asn_remote):
    global webscrub_url
    # test if url is reachable
    try:
        response = requests.get(f'{webscrub_url}asn/getgreip/{asn_remote}')
        logger.info(f'{response.status_code} - {response.reason} - {response.text}')
        return response.json()['gre_ip']
    except:
        logger.error('No se pudo conectar la terminacion del tunel gre en el WebScrub')

def get_tunnels():
    # obtener todos los tuneles que son ASNs
    cmd = ['ip','tunnel','ls']
    logger.info(' '.join(cmd))
    s = subprocess.run(cmd, stdout=subprocess.PIPE)
    asns = []
    if s.returncode == 0:
        for line in s.stdout.decode('utf-8').split('\n'):
            try:
                asn = int(line.split(':')[0])
                asns.append(asn)
            except:
                continue
    return asns

rutas_aplicadas = set()

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

    if message["type"] == "state":
        if message['neighbor']['state'] in ["down", "connected"]:
            logger.warning(f"Peer {message['neighbor']['state']}. Limpiando rutas")
            send_cmd('clear adj-rib')
            tuneles = get_tunnels()
            logger.info(f'Eliminando tuneles: {tuneles}')
            for tun in tuneles:
                logger.info(f'Eliminando tunel {tun}')
                remove_gre(tun, force=True)

    elif message["type"] == "update":
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
                create_or_up_gre(local, asn_remote)
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
                    down_gre(asn_remote)
                # remove_orphan_gre()

            

        except KeyError as detail:
            pass

