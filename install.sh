#!/bin/bash

#* [ExaBGP](https://github.com/Exa-Networks/exabgp):

if [[ -d /opt/exabgp/ ]]; then
    echo "Ya existe una instalación de ExaBGP en /opt/exabgp, borrando..."
    rm -rf /opt/exabgp/
fi

echo "Descargando ExaBGP en /opt/exabgp"
sudo git clone https://github.com/Exa-Networks/exabgp /opt/exabgp/
cd /opt/exabgp/
sudo git checkout 4.2.11

echo "Instalando ExaBGP"
sudo python3 -m zipapp -o /usr/local/sbin/exabgp -m exabgp.application:main  -p "/usr/bin/env python3" lib


chmod +x /opt/ScrubbingUNLP/start.sh
