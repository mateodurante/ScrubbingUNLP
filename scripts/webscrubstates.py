import requests
from sys import stdout
import logging
import socket
import json
import time
from sys import stdin, stdout
import base64

hostname = socket.gethostname()

logging.basicConfig(filename=f'/var/log/webscrubstates_{hostname}.log', level=logging.INFO)
logger = logging.getLogger(__name__)

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

def get_if_exists(d, key_list):
    try:
        if len(key_list) == 0:
            return d
        else:
            if type(d) == list and type(key_list) == int:
                return get_if_exists(d[key_list], key_list[1:])
            else:
                return get_if_exists(d[key_list[0]], key_list[1:])
    except:
        return ''

while True:
    line = stdin.readline().strip()
    # When the parent dies we are seeing continual newlines, so we only access so many before       #stopping
    if line == "":
        counter += 1
        if counter > 100:
            break
        continue
    counter = 0

    logger.warn('Recibido: ' + line)
    message = json.loads(line)

    try:
        related_asn = get_if_exists(message, ['neighbor', 'message', 'update', 'attribute', 'as-path'])
        if related_asn:
            related_asn = related_asn[0]
        related_network = get_if_exists(message,['neighbor', 'message', 'update', 'announce', 'ipv4 unicast', message['neighbor']['address']['peer'], 0, 'nlri'])
        msg = {
            'host': message['host'],
            'time': message['time'],
            'counter': message['counter'],
            'type': message['type'],
            'related_asn': related_asn,
            'related_network': related_network,
            'neighbor': { 
                'address': { 
                    'local': message['neighbor']['address']['local'], 
                    'peer': message['neighbor']['address']['peer']
                }, 
                'asn': { 
                    'local': message['neighbor']['asn']['local'], 
                    'peer': message['neighbor']['asn']['peer']
                }, 
                'direction': get_if_exists(message, ['neighbor', 'direction']),
                'state': get_if_exists(message, ['neighbor', 'state']),
                'state': get_if_exists(message, ['neighbor', 'state'])
            },
            'raw': base64.b64encode(line.encode('utf-8')).decode('utf-8')
        }
        requests.post(f"{webscrub_url}peermessage/add", json=msg)
        logger.info(msg)

    except KeyError as detail:
        logger.error(f'Error al parsear el mensaje: {message} - {detail}')
        


