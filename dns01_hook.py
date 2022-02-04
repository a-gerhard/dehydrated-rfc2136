#!/usr/bin/python3

import dns
import dns.tsigkeyring
import dns.update
import dns.query
import socket
import sys
import yaml

CONFIG = {}
DEBUG = False

def read_config_file(filename):
    global CONFIG
    global DEBUG
    with open(filename, 'r') as f:
        configfile = yaml.safe_load(f)
    CONFIG = configfile['domains']
    DEBUG = configfile.get('DEBUG', False)


def get_config(domain_to_verify):
    config = CONFIG.get(domain_to_verify)
    for item in ('zone', 'dns_server', 'tsig_keyname', 'tsig_secret'):
        if item not in config:
            raise Exception(f'{item} missing from domain config {domain_to_verify}')
    dns_server = socket.gethostbyname(config['dns_server'])
    zone = (config['zone'] if config['zone'].endswith(".") else f'{config["zone"]}.')
    keyring = dns.tsigkeyring.from_text({config['tsig_keyname']: config['tsig_secret']})
    return zone, config['record'], dns_server, config['tsig_keyname'], keyring

def deploy(domain_to_verify, challenge_string):
    zone, record, dns_server, keyname, keyring = get_config(domain_to_verify)
    update = dns.update.Update(zone, keyring=keyring, keyname=keyname, keyalgorithm='hmac-md5.sig-alg.reg.int')
    update.add(record, 3600, 'TXT', challenge_string)
    result = dns.query.tcp(update, dns_server)
    if DEBUG:
        print(f"Deploying challenge for {domain_to_verify}")
        print(result)
    return result.rcode() == dns.rcode.NOERROR

def cleanup(domain_to_verify, challenge_string):
    zone, record, dns_server, keyname, keyring = get_config(domain_to_verify)
    update = dns.update.Update(zone, keyring=keyring, keyname=keyname, keyalgorithm='hmac-md5.sig-alg.reg.int')
    update.delete(record, 'TXT', challenge_string)
    result = dns.query.tcp(update, dns_server)
    if DEBUG:
        print(f"Cleaning up challenge for {domain_to_verify}")
        print(result)
    else:
        if result.rcode() == dns.rcode.NOERROR:
            print(f'ERROR: DNS server returned rcode {dns.rcode()}')
    return result.rcode() == dns.rcode.NOERROR



def dns01(operation, domain_to_verify, _, challenge_string):

    ops = {
        'deploy_challenge': deploy,
        'clean_challenge': cleanup,
        'deploy_cert': None,
        'invalid_challenge': None,
        'request_failure': None
    }

    if not ops.get(operation):
        return True

    return ops.get(operation)(domain_to_verify, challenge_string)



if __name__ == '__main__':
    read_config_file('/etc/dehydrated/dns01.yml')

    if DEBUG:
        print(sys.argv)

    if len(sys.argv) == 2 and sys.argv[1] == "testconfigload":
        print(CONFIG.keys())
        sys.exit(0)

    if len(sys.argv) != 5:
        sys.exit(0)

    if dns01(*sys.argv[1:]):
        sys.exit(0)
    else:
        sys.exit(1)
