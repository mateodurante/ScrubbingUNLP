# ScrubbingUNLP

## Qué es?

ScrubbingUNLP es una plataforma diseñada para controlar múltiples nodos de scrubbing centers, abiertos, para que cualquiera pueda implementarlos. Ideal para organizaciones de bajos recursos.

La plataforma consta de tres componentes escenciales, por un lado los nodos ExaBGP que deberán estar unibicados en diversos puntos de Internet con peering BGP listos para publicar redes de los ASN pertenecientes al scrubbing implementado. 

Otra componentes es la plataforma web "WebScrub" que corre en el nodo central de la red de ExaBGP, desde esta plataforma puede estar montada sobre cualquier máquina con Internet. Desde esta plataforma un administrador será capaz de crear usuarios y asignarles AS, estos usuarios son los que publicarán luego redes de sus AS para que el tráfico de Internet atraviese los scrubbing centers de la red ExaBGP, y luego se aplicarán reglas FlowSpec también anunciadas por los usuarios a través de la plataforma WebScrub.

Finalmente, los usuarios del sistema, administradores de los respectivos AS, deben tener configurado en una VM dentro de su organización un túnel GRE contra cada uno de los scrubbing centers de la red por donde el tráfico saldrá limpio.

# Instalación

* [ExaBGP](https://github.com/Exa-Networks/exabgp):
  * `cd /opt/`
  * `sudo git clone https://github.com/Exa-Networks/exabgp && cd exabgp/`
  * `sudo git checkout 4.2.11`
  * `sudo python3 -m zipapp -o /usr/local/sbin/exabgp -m exabgp.application:main  -p "/usr/bin/env python3" lib`

* Utils:
  * `sudo apt install bridge-utils`


# Cómo correrlo?

Se debe correr sobre el nodo central la plataforma WebScrub.

```bash
python3 manage.py runserver 0.0.0.0:80
```

Sobre el mismo nodo también debe ejecutarse exabgp con la configuración del nodo central y la IP del nodo:

`bash start.sh -c config_examples/exabgpCentral.ini -b IP`

Finalmente se debe ejecutar sobre cada uno de los nodos de la red ExaBGP que sean scrubbing centers con su respectiva configuración e IP:

`bash start.sh -c config_examples/exabgpScrubbingN.ini -b IP`


# Configurar los túneles

Para que el tráfico limpio llegue a la organización es necesario configurar VMs en las organizaciones con túneles hacia cada scrubbing center de la red ExaBGP.

Del lado de los scrubbing centers es necesario definirlo ahora, hasta que el sistema pueda crearlos automáticamente. Es en cada scrubbing center, por cada cliente:

```bash
ip tunnel add <ASN-cliente> mode gre remote <IP-extremo-tunel-GRE-VM-Cliente> local <IP-ScrubbingCenterN> ttl 255
ip link set <ASN-cliente> up
```

En las VMs de los clientes por donde saldrá el tráfico limpio se configura el otro extremo del túnel. En cada VM de cliente, por cada scrubbing center disponible:

```bash
ip tunnel add scrub<Numero-ScrubbingN> mode gre remote <IP-ScrubbingN> local <IP-extremo-tunel-GRE-VM-Cliente>  ttl 255
ip link set scrub<Numero-ScrubbingN> up
```
