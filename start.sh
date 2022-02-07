#!/bin/bash

POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    -b|--bind-ip)
      BINDIP="$2"
      shift # past argument
      shift # past value
      ;;
    -c|--config-file)
      CONFIGFILE="$2"
      shift # past argument
      shift # past value
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

[ -z ${BINDIP} ] && echo "Se necesita el parametro BINDIP" && exit 1
[ -z ${CONFIGFILE} ] && echo "Se necesita el parametro CONFIGFILE" && exit 1

echo "BINDIP     = ${BINDIP}"
echo "CONFIGFILE = ${CONFIGFILE}"


# exit 0

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo $SCRIPT_DIR

if [ "$(id -u)" != "0" ]; then
   echo "Este script debés ejecutarlo como root, gato" 1>&2
   exit 1
fi

echo "Script para simplificarnos la vida, chabón."

[[ ! -d /opt/exabgp/ ]] && echo "Se necesita exabgp en /opt/exabgp/ " && exit 1

[[ -d /opt/exabgp/scripts/ ]] || mkdir -p /opt/exabgp/scripts/

echo "Moviendo scripts de Python a /opt/exabgp/scripts/"

cp $SCRIPT_DIR/scripts/* /opt/exabgp/scripts/

echo "Habilitando forwarding IPv4."

sysctl -w net.ipv4.ip_forward=1

echo "Ejecutando ExaBGP"

mkfifo /run/exabgp.{in,out}; chmod 777 /run/exabgp.{in,out}

env exabgp_daemon_daemonize=false exabgp_tcp_bind=$BINDIP exabgp_daemon_user=root /opt/exabgp/sbin/exabgp $CONFIGFILE
