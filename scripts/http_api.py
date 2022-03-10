from flask import Flask, request
from sys import stdout
import logging
import socket
import subprocess
import os

# Disable printing to stdout
os.environ['WERKZEUG_RUN_MAIN'] = 'true'

hostname = socket.gethostname()

logging.basicConfig(filename=f'/var/log/http_api_{hostname}.log', level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Setup a command route to listen for prefix advertisements
@app.route('/', methods=['POST'])
def command():
    command = request.form['command']
    logger.info(command)
    stdout.write('%s\n' % command)
    stdout.flush()
    return '%s\n' % command

# Run BGP commands
@app.route('/exabgpcli', methods=['POST'])
def exabgpcli():
    command = request.form['command']
    p = subprocess.Popen(['/opt/exabgp/bin/exabgpcli']+command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return {'stdout': stdout.decode('utf-8'), 'stderr': stderr.decode('utf-8'), 'returncode': p.returncode}

if __name__ == '__main__':
    app.run(host="0.0.0.0")
