#!/bin/bash

#* [ExaBGP](https://github.com/Exa-Networks/exabgp):
cd /opt/
sudo git clone https://github.com/Exa-Networks/exabgp && cd exabgp/
sudo git checkout 4.2.11
sudo python3 -m zipapp -o /usr/local/sbin/exabgp -m exabgp.application:main  -p "/usr/bin/env python3" lib

