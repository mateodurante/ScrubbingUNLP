#!/usr/bin/env python
import os
import sys
import json
import copy
import pprint
import logging
from subprocess import Popen, PIPE
import struct


NETWORKS = {
	"33"  : "172.16.1.0/24",	# Scrubbing 1
	"5692" : "172.16.3.0/24",	# UNLP
	"52376"  : "172.16.1.0/24",	# Scrubbing 2 (CABASE)
}

MY_GRE_IP = "172.16.1.1"

# apt-get install -y python-redis python-pip
# pip install rq

exabgp_log = open("/tmp/exabgp.log", "a")

logging.basicConfig(filename='/tmp/firewall_queue_worker.log', level=logging.INFO)
#logging.basicConfig(filename='/var/log/firewall_queue_worker.log', level=logging.INFO)
logger = logging.getLogger(__name__)

firewall_backend = 'iptables'

fw_comment_text = "Received from: "

insertion_policy = "-I"

class AbstractFirewall:
    def generate_rules(self, peer_ip, pyflow_list, policy):
        generated_rules = []
        for pyflow_rule in pyflow_list:
            flow_is_correct = self.check_pyflow_rule_correctness(pyflow_rule)

            if not flow_is_correct:
                return

            generated_rules.append(self.generate_rule(peer_ip, pyflow_rule, policy))

        return generated_rules
    def check_pyflow_rule_correctness(self, pyflow_rule):
        allowed_actions = [ 'allow', 'deny', 'rate-limit' ]
        allowed_protocols = [ 'udp', 'tcp', 'all', 'icmp' ]

        if not pyflow_rule['action'] in allowed_actions:
            logger.info("Bad action: " + pyflow_rule['action'])
            return False

        if not pyflow_rule['protocol'] in allowed_protocols:
            logger.info("Bad protocol: " + pyflow_rule['protocol'])
            return False

        if len (pyflow_rule['source_port']) > 0 and not pyflow_rule['source_port'].isdigit():
            logger.warning("Bad source port format")
            return False

        if len (pyflow_rule['packet_length']) > 0 and not pyflow_rule['packet_length'].isdigit():
            logger.warning("Bad packet length format")
            return False

        if len (pyflow_rule['target_port']) > 0 and not pyflow_rule['target_port'].isdigit():
            return "Bad target port: " + pyflow_rule['target_port']
            return False

        return True

class Iptables(AbstractFirewall):
    def __init__(self):
        self.iptables_path = '/sbin/iptables'
        # In some cases we could work on INPUT/OUTPUT
        self.working_chain = 'FORWARD'
    def flush_rules(self, peer_ip, pyflow_list):
        # iptables -nvL FORWARD -x --line-numbers
        logger.info("We will flush all rules from peer " + peer_ip)

        if pyflow_list == None:
            execute_command_with_shell(self.iptables_path, ['--flush', self.working_chain])
            return True

        rules_list = self.generate_rules(peer_ip, pyflow_list, "-D")
        if rules_list != None and len(rules_list) > 0:
            for iptables_rule in rules_list:
                search_by = iptables_rule[-1].replace('-D', insertion_policy)
                proc1 = Popen(["iptables-save"], stdout=PIPE)
                out, err = proc1.communicate()
                out = out.decode("utf-8")
                for line in out.split('\n'):
                    if search_by in line:
                        proc2 = Popen("iptables -D "+line[3:], shell=True)
        else:
            logger.error("Generated rule list is blank!")

    def flush(self):
        logger.info("We will flush all rules from peer " + peer_ip)
        execute_command_with_shell(self.iptables_path, ['--flush', self.working_chain])

    def add_rules(self, peer_ip, pyflow_list):
        rules_list = self.generate_rules(peer_ip, pyflow_list, insertion_policy)

        if rules_list != None and len(rules_list) > 0:
            for iptables_rule in rules_list:
                execute_command_with_shell(self.iptables_path, iptables_rule)
        else:
            logger.error("Generated rule list is blank!")

    def generate_rule(self, peer_ip, pyflow_rule, policy):
        iptables_arguments = [policy, self.working_chain]

        if pyflow_rule['protocol'] != 'all':
            iptables_arguments.extend(['-p', pyflow_rule['protocol']])

        if pyflow_rule['source_host'] != 'any':
            iptables_arguments.extend(['-s', pyflow_rule['source_host']])

        if pyflow_rule['target_host'] != 'any':
            iptables_arguments.extend(['-d', pyflow_rule['target_host']])

        # We have ports only for udp and tcp protocol
        if pyflow_rule['protocol'] == 'udp' or pyflow_rule['protocol'] == 'tcp':
            if 'source_port' in pyflow_rule and len(pyflow_rule['source_port']) > 0:
                iptables_arguments.extend(['--sport', pyflow_rule['source_port']])

            if 'target_port' in pyflow_rule and len(pyflow_rule['target_port']) > 0:
                iptables_arguments.extend(['--dport', pyflow_rule['target_port']])

        base_rule = ' '.join(iptables_arguments)

        if 'tcp_flags' in pyflow_rule and len(pyflow_rule['tcp_flags']) > 0:
            # ALL means we check all flags for packet
            iptables_arguments.extend(['--tcp-flags', 'ALL', ",".join(pyflow_rule['tcp_flags'])])

        if pyflow_rule['fragmentation']:
            iptables_arguments.extend(['--fragment'])

        # We could specify only range here, list is not allowed
        if 'packet-length' in pyflow_rule:
            iptables_arguments.extend(['-m', 'length', '--length', pyflow_rule[packet-length]])

        if pyflow_rule['action'] == 'rate-limit':
            rule_name = pyflow_rule['source_host']+pyflow_rule['target_host']+\
                pyflow_rule['protocol']+pyflow_rule['source_port']+pyflow_rule['target_port']
            iptables_arguments.extend(['-m', 'hashlimit'])
            #iptables_arguments.extend(['--hashlimit-srcmask', '32'])
            iptables_arguments.extend(['--hashlimit-mode', 'srcip,dstip'])
            iptables_arguments.extend(['--hashlimit-above', pyflow_rule['action_value']+"b/s"])
            # hashlimit-name needs to be short and diferent between diferent rules
            iptables_arguments.extend(['--hashlimit-name', str(abs(hash(rule_name)) % (10 ** 8))])

        iptables_arguments.extend(['-j', 'DROP'])

        iptables_arguments.extend(['-m', 'comment', '--comment', \
            "{0} {1} {2}".format(fw_comment_text, str(peer_ip), base_rule)])

        pp = pprint.PrettyPrinter(indent=4)
        logger.info("Will run iptables command: " + pp.pformat(iptables_arguments))

        print(iptables_arguments)
        return iptables_arguments


def execute_command_with_shell(command_name, arguments):
    args = [ command_name ]

    if arguments != None:
        args.extend( arguments )

    Popen( args );


firewall = None;

if (firewall_backend == 'netmap-ipfw'):
    firewall = Ipfw()
elif firewall_backend == 'iptables':
    firewall = Iptables()
else:
    logger.error("Firewall" + firewall_backend + " is not supported")
    sys.exit("Firewall" + firewall_backend + " is not supported")

def manage_flow(action, peer_ip, flow, flow_body, firewall):
    allowed_actions = [ 'withdrawal', 'announce' ]
    logger.warning("Action " + action + " checking...")

    if action not in allowed_actions:
        logger.warning("Action " + action + " is not allowed")
        return False

    pp = pprint.PrettyPrinter(indent=4)
    logger.info(pp.pformat(flow))

    if action == 'withdrawal' and flow == None:
        firewall.flush_rules(peer_ip, None)
        return True
    elif action == 'withdrawal' and flow != None:
        py_flow_list = convert_exabgp_to_pyflow(flow, flow_body)
        logger.info("Call flush_rules non None") 
        logger.info("PyFlow: "+str(py_flow_list))
        firewall.flush_rules(peer_ip, py_flow_list)
        return True

    py_flow_list = convert_exabgp_to_pyflow(flow, flow_body)
    return firewall.add_rules(peer_ip, py_flow_list)

def convert_exabgp_to_pyflow(flow, flow_body):
    # Flow in python format, here
    # We use customer formate because ExaBGP output is not so friendly for firewall generation
    logger.info("In convert: "+str(flow))
    current_flow = {
        'action'        : 'deny',
        'action_value'  : None,
        'protocol'      : 'all',
        'source_port'   : '',
        'source_host'   : 'any',
        'target_port'   : '',
        'target_host'   : 'any',
        'fragmentation' : False,
        'packet_length' : '',
        'tcp_flags'     : [],
    }

    # Analyzing extended community:
    # This may come parsed from exabgp but not by now (https://github.com/Exa-Networks/exabgp/issues/265) 
    # RFC 5575 (https://tools.ietf.org/html/rfc5575#section-7)
    # ICMP: 0000002C800E1100018500000B0120B617006F02000381014001010040020602010000163CC010088006000044800000
    # UDP : 0000002F800E1400018500000E0120B617006F020003811106817B4001010040020602010000163CC0100880060000462D9C00
    # Checking extended-community rate limit 0x8006
    extended_community = flow_body[-16:]
    if extended_community[0:4] == "8006":
        current_flow['action'] = 'rate-limit'
        # Hex is formated as floating point
        current_flow['action_value'] = str(int(struct.unpack('!f', extended_community[8:].decode('hex'))[0]))

    # But we definitely could have MULTIPLE ports here
    if 'packet-length' in flow:
        current_flow['packet_length'] = flow['packet-length'][0].lstrip('=')

    # We support only one subnet for source and destination
    if 'source-ipv4' in flow:
        current_flow['source_host'] = flow["source-ipv4"][0]

    if 'destination-ipv4' in flow:
        current_flow['target_host'] = flow["destination-ipv4"][0]

    if 'tcp-flags' in flow and len(flow['tcp-flags']) > 0:
        for tcp_flag in flow['tcp-flags']:
            current_flow['tcp_flags'].append(tcp_flag.lstrip('='))

    if current_flow['source_host'] == "any" and current_flow['target_host'] == "any":
        logger.info( "We can't process this rule because it will drop whole traffic to the network" )
        return False

    if 'destination-port' in flow:
        current_flow['target_port'] = flow['destination-port'][0].lstrip('=')

    if 'source-port' in flow:
        current_flow['source_port'] = flow['source-port'][0].lstrip('=');

    if 'fragment' in flow:
        if '=is-fragment' in flow['fragment']:
            current_flow['fragmentation'] = True

    pyflow_list = []

    if 'protocol' in flow:

        for current_protocol in flow['protocol']:
            current_flow['protocol'] = current_protocol.lstrip('=')
            pyflow_list.append(copy.copy(current_flow))
    else:
        current_flow['protocol'] = 'all'
        pyflow_list.append(current_flow)
    
    return pyflow_list


# Funcion para crear el tunel GRE en Scrubbing (por alguna razon, no funciona correctamente en un archivo separado)
def create_gre(line):
    json_line = json.loads(line)
    try:
        if json_line["type"] == "update":
            neighbor = json_line["neighbor"]
            remote = neighbor["address"]["peer"]
            local = neighbor["address"]["local"]
            asn_remote = neighbor["asn"]["peer"]
            if "announce" in neighbor["message"]["update"].keys() and neighbor["direction"] == "receive":
                if "ipv4 unicast" in neighbor["message"]["update"]["announce"].keys():
                    command = """
ip tunnel add {2} mode gre remote {0} local {1} ttl 255
ip link set {2} up
ip addr add {3} dev {2}
ip route add {4} dev {2}
"""
                    os.system(command.format(remote, local, asn_remote, MY_GRE_IP, NETWORKS[asn_remote]))
                    return True
    except KeyError:
        pass
    return None

while True:
    try:
        line = sys.stdin.readline().strip()
        # print >> sys.stderr, "GOT A LINE"
        logger.warn(line)
        sys.stdout.flush()
        counter = 0

# { "exabgp": "3.5.0", "time": 1431716393, "host" : "synproxied.fv.ee", "pid" : 2599, "ppid" : 2008, "counter": 1, "type": "update", "neighbor": { "address": { "local": "10.0.3.115", "peer": "10.0.3.114" }, "asn": { "local": "1234", "peer": "65001" }, "direction": "receive", "message": { "update": { "attribute": { "origin": "igp", "as-path": [ 65001 ], "confederation-path": [], "extended-community": [ 9225060886715039744 ] }, "announce": { "ipv4 flow": { "no-nexthop": { "flow-0": { "destination-ipv4": [ "10.0.0.2/32" ], "source-ipv4": [ "10.0.0.1/32" ], "protocol": [ "=tcp" ], "destination-port": [ "=3128" ], "string": "flow destination-ipv4 10.0.0.2/32 source-ipv4 10.0.0.1/32 protocol =tcp destination-port =3128" } } } } } } } }

# u'destination-ipv4': [u'10.0.0.2/32'],
# u'destination-port': [u'=3128'],
# u'protocol': [u'=tcp'],
# u'source-ipv4': [u'10.0.0.1/32'],
# u'string': u'flow destination-ipv4 10.0.0.2/32 source-ipv4 10.0.0.1/32 protocol =tcp destination-port =3128'}

# Peer shutdown notification:
# { "exabgp": "3.5.0", "time": 1431900440, "host" : "filter.fv.ee", "pid" : 8637, "ppid" : 8435, "counter": 21, "type": "state", "neighbor": { "address": { "local": "10.0.3.115", "peer": "10.0.3.114" }, "asn": { "local": "1234", "peer": "65001" }, "state": "down", "reason": "in loop, peer reset, message [closing connection] error[the TCP connection was closed by the remote end]" } }

        # Llamado a crear GRE tunnel, se verifica dentro de la funcion el tipo de mensaje recibido:
        #create_gre(line)

        # Fix bug: https://github.com/Exa-Networks/exabgp/issues/269
        line = line.replace('0x800900000000000A', '"0x800900000000000A"')
        #io = StringIO(line)        
        sys.stderr.write(line)
        
        try:
            decoded_update = json.loads(line)
        except:
            sys.stderr.write("No se puede decodear: " + line)
            break

        pp = pprint.PrettyPrinter(indent=4, stream=sys.stderr)
        pp.pprint(decoded_update)

        try:
            current_flow_announce = decoded_update["neighbor"]["message"]["update"]["announce"]["ipv4 flow"]
            peer_ip = decoded_update['neighbor']['address']['peer']

            for next_hop in current_flow_announce:
                flow_announce_with_certain_hop = current_flow_announce[next_hop]

                for flow in flow_announce_with_certain_hop:
                    pp.pprint(flow)
                    manage_flow('announce', peer_ip, flow, decoded_update['body'], firewall)
        except KeyError:
            pass

        try:
            current_flow_withdraw = decoded_update["neighbor"]["message"]["update"]["withdraw"]["ipv4 flow"]
            peer_ip = decoded_update['neighbor']['address']['peer']
            for flow in current_flow_withdraw:
                pp.pprint(flow)
                manage_flow('withdrawal', peer_ip, flow, decoded_update['body'], firewall)
        except KeyError:
            pass

        # We got notification about neighbor status
        if 'type' in decoded_update and decoded_update['type'] == 'state':
            if 'state' in decoded_update['neighbor'] and decoded_update['neighbor']['state'] == 'down':
                peer_ip = decoded_update['neighbor']['address']['peer']
                print ("We received notification about peer down for: " + peer_ip, file=sys.stderr)
                manage_flow('withdrawal', peer_ip, None, None, firewall)

        exabgp_log.write(line + "\n")
    except KeyboardInterrupt:
        pass
    except IOError:
        # most likely a signal during readline
        pass

