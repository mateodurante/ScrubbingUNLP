#!/usr/bin/env python
from asyncio import subprocess
import sys
import json
import copy
import logging
import struct
import socket
import subprocess
import binascii

## TODO: apply rules as defined in RFC https://datatracker.ietf.org/doc/html/rfc5575#section-5.1 and change in webscrub

hostname = socket.gethostname()
logging.basicConfig(filename=f'/var/log/firewall_{hostname}.log', level=logging.INFO)
logger = logging.getLogger(__name__)

## 'iptables' only ('netmap-ipfw' not implemented)
firewall_backend = 'iptables'
insertion_policy = "-I"


class AbstractFirewall:
    fw_comment_text = "Received from: "

    def generate_rules(self, peer_ip, pyflow_list, policy):
        logger.info(f"In generate_rules: {peer_ip} {pyflow_list} {policy}")
        generated_rules = []
        for pyflow_rule in pyflow_list:
            flow_is_correct = self.check_pyflow_rule_correctness(pyflow_rule)
            
            if not flow_is_correct:
                return

            generated_rules.append(self.generate_rule(peer_ip, pyflow_rule, policy))

        return generated_rules
    

    def check_pyflow_rule_correctness(self, pyflow_rule):
        logger.info(f"In check_pyflow_rule_correctness: {pyflow_rule}")
        allowed_actions = [ 'allow', 'deny', 'rate-limit' ]
        allowed_protocols = [ 'udp', 'tcp', 'all', 'icmp' ]

        if not pyflow_rule['action'] in allowed_actions:
            logger.error("Bad action: " + pyflow_rule['action'])
            return False

        if not pyflow_rule['protocol'] in allowed_protocols:
            logger.error("Bad protocol: " + pyflow_rule['protocol'])
            return False

        if len(pyflow_rule['source_port']) > 0:
            ports = pyflow_rule['source_port'].split(',')
            for port in ports:
                prange = port.split(':')
                if not prange[0].isdigit():
                    logger.error("Bad source port: " + prange[0])
                    return False
                if len(prange) > 1 and not prange[1].isdigit():
                    logger.error("Bad source port: " + prange[1])
                    return False

        if len(pyflow_rule['target_port']) > 0:
            ports = pyflow_rule['target_port'].split(',')
            for port in ports:
                prange = port.split(':')
                if not prange[0].isdigit():
                    logger.error("Bad target port: " + prange[0])
                    return False
                if len(prange) > 1 and not prange[1].isdigit():
                    logger.error("Bad target port: " + prange[1])
                    return False

        if len(pyflow_rule['packet_length']) > 0 and not pyflow_rule['packet_length'].isdigit():
            logger.warning("Bad packet length format")
            return False

        logger.info('PyFlow rule is correct')
        return True


    def execute_command_with_shell(self, command_name, arguments=[], shell=False):
        ## Run command
        if shell:
            cmd = f"{command_name} {' '.join(arguments)}"
            logger.info(f"Executing command: {cmd}")
        else:
            cmd = [command_name] + arguments
            logger.info(f"Executing command: {' '.join(cmd)}")

        try:
            s = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell)
            logger.info(f"Command output: {s.stdout.decode('utf-8')}")
            logger.info(f"Command error: {s.stderr.decode('utf-8')}")
            logger.info(f"Command return code: {s.returncode}")
            return s.stdout.decode('utf-8'), s.stderr.decode('utf-8'), s.returncode
        except subprocess.CalledProcessError as e:
            logger.exception(f"Command {cmd} failed with error: {e.stderr}")
            return []


    def manage_flow(self, action, peer_ip, flow, flow_body, extended_community=None):
        ## Convert and apply rules
        logger.info(f"In manage_flow: {action} {peer_ip} {flow} {flow_body} {self}")

        if action == 'flush-all':
            self.flush_rules(peer_ip, None)
            return True

        elif action == 'withdrawal':
            py_flow_list = self.convert_exabgp_to_pyflow(flow, flow_body, extended_community=extended_community)
            logger.info("Call flush_rules non None") 
            logger.info(f"PyFlow: {py_flow_list}")
            self.flush_rules(peer_ip, py_flow_list)
            return True

        elif action == 'announce':
            py_flow_list = self.convert_exabgp_to_pyflow(flow, flow_body, extended_community=extended_community)
            return self.add_rules(peer_ip, py_flow_list)

        logger.error(f"Action {action} is not allowed")
        return False


    def convert_exabgp_to_pyflow(self, flow, flow_body, extended_community=None):
        # Flow in python format, here
        # We use customer formate because ExaBGP output is not so friendly for firewall generation
        logger.info(f"In convert: {flow}")
        current_flow = {
            'action'            : 'allow',
            'rate_limit_value'  : None,
            'protocol'          : 'all',
            'source_port'       : '',
            'source_host'       : 'any',
            'target_port'       : '',
            'target_host'       : 'any',
            'fragmentation'     : False,
            'packet_length'     : '',
            'tcp_flags'         : [],
        }

        # Analyzing extended community:
        # "extended-community": [
        #     {
        #         "value": 9225060886715039744,
        #         "string": "rate-limit:0"
        #     }
        # ]
        #  https://datatracker.ietf.org/doc/html/rfc5575#section-7
        #    Traffic-rate:  The traffic-rate extended community is a non-
        #    transitive extended community across the autonomous-system
        #    boundary and uses following extended community encoding:
        #
        #      The first two octets carry the 2-octet id, which can be
        #      assigned from a 2-byte AS number.  When a 4-byte AS number is
        #      locally present, the 2 least significant bytes of such an AS
        #      number can be used.  This value is purely informational and
        #      should not be interpreted by the implementation.
        #
        #      The remaining 4 octets carry the rate information in IEEE
        #      floating point [IEEE.754.1985] format, units being bytes per
        #      second.  A traffic-rate of 0 should result on all traffic for
        #      the particular flow to be discarded.
        #       8006 0000 0000 0000 00
        #      | 1  |  2 |    3    | 4|
        #      1: Community type (0x8006)
        #      2: AS, first 2 bytes when is 4 bytes AS
        #      3: Rate limit, 4 bytes
        #      4: (optional) AS, last 2 bytes when is 4 bytes AS
        if extended_community:
            logger.info(f"Extended community: {extended_community}")
            for ec in extended_community:
                hec = hex(ec['value'])[2:]
                if hec[:4] == '8006': # Community type: Traffic-rate (first 2 bytes)
                    current_flow['action'] = 'rate-limit'
                    current_flow['rate_limit_value'] = int(struct.unpack('!f', bytes.fromhex(hec[8:16]))[0]) # 4 bytes: rate value
                    logger.info(f"Rate limit value: {current_flow['rate_limit_value']}")
                    break

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
            logger.info("We can't process this rule because it will drop whole traffic to the network")
            return False

        if 'destination-port' in flow:
            plist = []
            for p in flow['destination-port']:
                if p.startswith('='):
                    plist.append(p.lstrip('='))
                elif p.startswith('>') and '&' in p:
                    plist.append(p.replace('>', '').replace('&<', ':'))
                else:
                    logger.error('Unsupported port format: ' + p)
                current_flow['target_port'] = ','.join(plist)

        if 'source-port' in flow:
            plist = []
            for p in flow['source-port']:
                if p.startswith('='):
                    plist.append(p.lstrip('='))
                elif p.startswith('>') and '&<' in p:
                    plist.append(p.replace('>', '').replace('&<', ':'))
                else:
                    logger.error('Unsupported port format: ' + p)
                current_flow['source_port'] = ','.join(plist)

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




class Iptables(AbstractFirewall):

    def __init__(self):
        self.bin_path = '/sbin/iptables'
        # In some cases we could work on INPUT/OUTPUT
        self.working_chain = 'FORWARD'


    def flush_rules(self, peer_ip, pyflow_list):
        # iptables -nvL FORWARD -x --line-numbers
        logger.info(f"Iptables: flush all rules from peer {peer_ip}")

        if pyflow_list == None:
            self.execute_command_with_shell(self.bin_path, arguments=['--flush', self.working_chain])
            return True

        rules_list = self.generate_rules(peer_ip, pyflow_list, "-D")
        if rules_list != None and len(rules_list) > 0:
            for iptables_rule in rules_list:
                search_by = iptables_rule[-1].replace('-D', insertion_policy)
                res1 = self.execute_command_with_shell("iptables-save")
                if res1:
                    for line in res1[0].split('\n'):
                        if search_by in line:
                            res2 = self.execute_command_with_shell(f"{self.bin_path} -D {line[3:]}", shell=True)
                            ## Evitar que se borren todas las reglas
                            break
        else:
            logger.error("Iptables flush_rules: Generated rule list is empty!")


    def flush(self):
        logger.info("Iptables: flush all rules")
        self.execute_command_with_shell(self.bin_path, arguments=['--flush', self.working_chain])


    def add_rules(self, peer_ip, pyflow_list):
        logger.info(f"Iptables add_rules peer_ip: {peer_ip} pyflow_list: {pyflow_list}")
        rules_list = self.generate_rules(peer_ip, pyflow_list, insertion_policy)

        if rules_list != None and len(rules_list) > 0:
            for iptables_rule in rules_list:
                self.execute_command_with_shell(self.bin_path, arguments=iptables_rule)
        else:
            logger.error("Iptables add_rules: Generated rule list is empty!")


    def generate_rule(self, peer_ip, pyflow_rule, policy):
        logger.info(f"Iptables generate_rule peer_ip: {peer_ip} pyflow_list: {pyflow_rule} policy: {policy}")
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
                iptables_arguments.extend(['-m','multiport','--sport', pyflow_rule['source_port']])

            if 'target_port' in pyflow_rule and len(pyflow_rule['target_port']) > 0:
                iptables_arguments.extend(['-m','multiport','--dport', pyflow_rule['target_port']])

        base_rule = ' '.join(iptables_arguments)

        if 'tcp_flags' in pyflow_rule and len(pyflow_rule['tcp_flags']) > 0:
            # ALL means we check all flags for packet
            iptables_arguments.extend(['--tcp-flags', 'ALL', ",".join(pyflow_rule['tcp_flags'])])

        if pyflow_rule['fragmentation']:
            iptables_arguments.extend(['--fragment'])

        # We could specify only range here, list is not allowed
        if 'packet-length' in pyflow_rule:
            iptables_arguments.extend(['-m', 'length', '--length', pyflow_rule['packet-length']])

        logger.info(f"Iptables generate_rule: {base_rule}")

        if pyflow_rule['action'] == 'deny':
            logger.info(f"Iptables action deny")
            iptables_arguments.extend(['-j', 'DROP'])
        elif pyflow_rule['action'] == 'allow':
            logger.info(f"Iptables action allow")
            iptables_arguments.extend(['-j', 'ACCEPT'])
        elif pyflow_rule['action'] == 'rate-limit':
            if pyflow_rule['rate_limit_value'] == 0:
                logger.info(f"Iptables action drop")
                iptables_arguments.extend(['-j', 'DROP'])
            else:
                logger.info(f"Iptables action rate-limit")
                rule_name = pyflow_rule['source_host']+pyflow_rule['target_host']+\
                    pyflow_rule['protocol']+pyflow_rule['source_port']+pyflow_rule['target_port']
                iptables_arguments.extend(['-m', 'hashlimit'])
                #iptables_arguments.extend(['--hashlimit-srcmask', '32'])
                iptables_arguments.extend(['--hashlimit-mode', 'srcip,dstip'])
                iptables_arguments.extend(['--hashlimit-above', f"{pyflow_rule['rate_limit_value']}b/s"])
                # hashlimit-name needs to be short and diferent between diferent rules
                iptables_arguments.extend(['--hashlimit-name', str(abs(hash(rule_name)) % (10 ** 8))])
                iptables_arguments.extend(['-j', 'DROP'])
        else:
            logger.error(f"Iptables: Unknown action {pyflow_rule['action']}")
            return None
        
        logger.info(f"Iptables action: {iptables_arguments}")

        comment = f'{self.fw_comment_text} {peer_ip} {base_rule}'
        iptables_arguments.extend(['-m', 'comment', '--comment', comment])

        logger.info(f"Iptables: Will run iptables command: {self.bin_path} {' '.join(iptables_arguments)}")

        return iptables_arguments


class Ipfw(AbstractFirewall):

    def __init__(self):
        raise Exception("Not implemented")






# { "exabgp": "3.5.0", "time": 1431716393, "host" : "synproxied.fv.ee", "pid" : 2599, "ppid" : 2008, "counter": 1, "type": "update", "neighbor": { "address": { "local": "10.0.3.115", "peer": "10.0.3.114" }, "asn": { "local": "1234", "peer": "65001" }, "direction": "receive", "message": { "update": { "attribute": { "origin": "igp", "as-path": [ 65001 ], "confederation-path": [], "extended-community": [ 9225060886715039744 ] }, "announce": { "ipv4 flow": { "no-nexthop": { "flow-0": { "destination-ipv4": [ "10.0.0.2/32" ], "source-ipv4": [ "10.0.0.1/32" ], "protocol": [ "=tcp" ], "destination-port": [ "=3128" ], "string": "flow destination-ipv4 10.0.0.2/32 source-ipv4 10.0.0.1/32 protocol =tcp destination-port =3128" } } } } } } } }

# u'destination-ipv4': [u'10.0.0.2/32'],
# u'destination-port': [u'=3128'],
# u'protocol': [u'=tcp'],
# u'source-ipv4': [u'10.0.0.1/32'],
# u'string': u'flow destination-ipv4 10.0.0.2/32 source-ipv4 10.0.0.1/32 protocol =tcp destination-port =3128'}

# Peer shutdown notification:
# { "exabgp": "3.5.0", "time": 1431900440, "host" : "filter.fv.ee", "pid" : 8637, "ppid" : 8435, "counter": 21, "type": "state", "neighbor": { "address": { "local": "10.0.3.115", "peer": "10.0.3.114" }, "asn": { "local": "1234", "peer": "65001" }, "state": "down", "reason": "in loop, peer reset, message [closing connection] error[the TCP connection was closed by the remote end]" } }


## End Classes

## Functions:

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


## Main

firewall_options = {
    'netmap-ipfw': Ipfw,
    'iptables': Iptables
}

if not firewall_backend in firewall_options.keys():
    logger.error("Firewall" + firewall_backend + " is not supported")
    sys.exit("Firewall" + firewall_backend + " is not supported")

firewall = firewall_options[firewall_backend]()

while True:
    try:
        line = sys.stdin.readline().strip()

        # When the parent dies we are seeing continual newlines, so we only access so many before       #stopping
        if line == "":
            counter += 1
            if counter > 100:
                break
            continue
        counter = 0

        logger.info(line)
        
        # Fix bug: https://github.com/Exa-Networks/exabgp/issues/269
        line = line.replace('0x800900000000000A', '"0x800900000000000A"')
        try:
            exa_msg = json.loads(line)
        except Exception as e:
            logger.error("Can't decode json: " + line)
        logger.info(f"MSG: {exa_msg}")

        
        ## We only process update messages
        ipv4_announce_flows = get_if_exists(exa_msg, ['neighbor', 'message', 'update', 'announce', 'ipv4 flow'])
        if ipv4_announce_flows:
            peer_ip = exa_msg['neighbor']['address']['peer']
            for next_hop, flow_announce_with_certain_hop in ipv4_announce_flows.items():
                for flow in flow_announce_with_certain_hop:
                    logger.info(f"Processing annouce flow: {flow} with next hop: {next_hop}")
                    ec = get_if_exists(exa_msg, ['neighbor', 'message', 'update', 'attribute', 'extended-community'])
                    firewall.manage_flow('announce', peer_ip, flow, exa_msg['body'], extended_community=ec)
        
        ## We only process withdraw messages
        ipv4_withdraw_flows = get_if_exists(exa_msg, ['neighbor', 'message', 'update', 'withdraw', 'ipv4 flow'])
        if ipv4_withdraw_flows:
            peer_ip = exa_msg['neighbor']['address']['peer']
            for flow in ipv4_withdraw_flows:
                logger.info(f"Processing withdraw flow: {flow}")
                ec = get_if_exists(exa_msg, ['neighbor', 'message', 'update', 'attribute', 'extended-community'])
                firewall.manage_flow('withdrawal', peer_ip, flow, exa_msg['body'], extended_community=ec)

        # We got notification about neighbor status, cleanup rules related to this peer
        if get_if_exists(exa_msg, ['type']) == 'state':
            if get_if_exists(exa_msg, ['neighbor', 'state']) in ['down', 'connected']:
                peer_ip = exa_msg['neighbor']['address']['peer']
                logger.info(f"We received notification about peer {peer_ip} is down/connected, cleaning up rules")
                ec = get_if_exists(exa_msg, ['neighbor', 'message', 'update', 'attribute', 'extended-community'])
                firewall.manage_flow('flush-all', peer_ip, None, None, extended_community=ec)

    except KeyboardInterrupt:
        pass
    except IOError:
        # most likely a signal during readline
        pass
    except Exception as e:
        logger.exception('Exception in main loop')
