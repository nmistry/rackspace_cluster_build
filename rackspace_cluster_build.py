#!/usr/bin/env python

import argparse
import itertools
import os
import pyrax
import re
import sys
import time
import yaml

from prettytable import PrettyTable

def create_network(name, cidr):
    cnw = pyrax.cloud_networks
    network = cnw.create(name, cidr=cidr)
    return network

def create_server(name,
                  image="Ubuntu 12.04 LTS (Precise Pangolin)",
                  flavor="8 GB Performance",
                  networks=None,
                  keyname=None):
    cs = pyrax.cloudservers
    server_image = cs.images.find(name=image)
    server_flavor = cs.flavors.find(name=flavor)

    server = cs.servers.create(name,
                    image=server_image,
                    flavor=server_flavor,
                    key_name=keyname,
                    nics=networks,
                    )
    return server

def generate_networks(network_list, environment, network_names=[]):
    net_name_list = []
    if network_names is not None:
        net_name_list = [ ' '.join([environment, n]) for n in network_names ]
    net_name_list.append('public')
    net_name_list.append('private')
    return [ { 'net-id': network_list[n]['net-id'] } for n in net_name_list ]

def create_blockstorage(volume_name, size=100, volume_type="SSD"):
    cbs=pyrax.cloud_blockstorage
    vol = cbs.create(
        name=volume_name,
        size=size,
        volume_type=volume_type)
    return vol

def attach_blockstorage(cloud_server, volume, mountpoint='/dev/xvdb'):
    volume.attach_to_instance(cloud_server, mountpoint=mountpoint)
    pyrax.utils.wait_until(volume, "status", "in-use", interval=10, attempts=0,
      verbose=True)

def customer_provision(environment, keyname):
    network_list={
    'public': {'net-id': '00000000-0000-0000-0000-000000000000'},
    'private': {'net-id': '11111111-1111-1111-1111-111111111111'}
    }

    loadbalancer_nodes = {}

    ## Provision all the networks
    for net_type in ['App', 'Database', 'Management']:
        net_name = ' '.join([environment, net_type])
        net = create_network(net_name, cidr_template.format(cidr_subnet))
        network_list[net_name]={'net-id': net.id }
        cidr_subnet+=1

    ## Provision all the servers
    for server in server_list:
        server_name = '.'.join([server['name'],environment])
        s = create_server(name=server_name,
            image=server['image'],
            flavor=server['flavor'],
            networks=generate_networks(network_list, environment, server['networks'],
            keyname=keyname))

        pyrax.utils.wait_until(s, "status", "ACTIVE", attempts=0,
                verbose=True)

        if 'block-storage' in server:
            attach_blockstorage(s,
                server['name'],
                environment,
                size=server['block-storage']['size'],
                volume_type=server['block-storage']['type'],
                mountpoint=server['block-storage']['mountpoint'])


def configure_keypairs(keyname,keypath):

    if keyname is None:
        return None

    cs = pyrax.cloudservers
    try:
        if cs.keypairs.find(name=keyname):
            return keyname
    except:    ### cheating here, but its ok for now
        with open(os.path.expanduser(keypath)) as keyfile:
            cs.keypairs.create(keyname, keyfile.read())
        return  keyname

    return None

def process_config(config):

    network_list={
        'public': {'net-id': '00000000-0000-0000-0000-000000000000'},
        'private': {'net-id': '11111111-1111-1111-1111-111111111111'}
    }

    ## setup the keypair
    keypair_name = configure_keypairs(config.get('ssh_keyname'), config.get('ssh_keyfile'))

    ## create all the private networks
    if 'private_networks' in config:
        for net in config['private_networks']:
            net_name = ' '.join([config['environment'], net['name']])
            cidr = net['cidr']
            print "==> Creating network {} - {}".format(net_name,cidr)
            cloud_network = create_network(net_name, cidr)
            network_list[net_name] = {'net-id': cloud_network.id}

    cloud_servers = []
    attach_list = []
    lb_servers = {}
    clb = pyrax.cloud_loadbalancers
    if 'load_balancers' in config:
        for lb in config['load_balancers']:
            lb_short_name = lb.get('name')
            lb_servers[lb_short_name] = {}

            lb_short_name = lb.get('name')
            lb_long_name = '.'.join([lb_short_name, config['environment']])
            lb_port = lb.get('port')
            lb_protocol = lb.get('protocol')
            vip_type = lb.get('vip_type', "PUBLIC")
            count = lb.get('count', 1)
            algorithm = lb.get('algorithm', "LEAST_CONNECTIONS")
            session_persistence = lb.get('session_persistence', "HTTP_COOKIE")
            connection_logging = lb.get('connection_logging', False)

            vip = clb.VirtualIP(type=vip_type)

            lb_servers[lb_short_name] = {'loadbalancers': [], 'nodes':[] }
            for i in range(1,count+1):
                lb_name="{0}{1:0>2}.{2}".format(lb_short_name, i, config['environment'])
                print "==> Creating load balancer {}".format(lb_name)
                l = clb.create(lb_name, port=lb_port, protocol=lb_protocol, virtual_ips=[vip])

                pyrax.utils.wait_until(l, "status", "ACTIVE", interval=5, attempts=30, verbose=True)

                ## This does not work just yet, need
                ## reuse the same VIP for multiple load balancers in a cluster
                ## if i == 1:
                ##    vip = l.virtual_ips[0]

                print "-- Setting lb algorithm to {}".format(algorithm)
                l.update(algorithm=algorithm)
                pyrax.utils.wait_until(l, "status", "ACTIVE", interval=5, attempts=30, verbose=True)

                print "-- Setting lb session_persistence to {}".format(session_persistence)
                l.session_persistence = session_persistence

                pyrax.utils.wait_until(l, "status", "ACTIVE", interval=5, attempts=30, verbose=True)

                if connection_logging:
                    print "-- Enabling lb connection logging"
                    l.connection_logging = connection_logging

                lb_servers[lb_short_name]['loadbalancers'].append(l)

    if 'servers' in config:
        for server in config['servers']:
            server_name = '.'.join([server['name'],config['environment']])
            server_image = server.get('image', config['default_server_image'])
            server_flavor = server.get('flavor', config['default_server_flavor'])
            server_networks=generate_networks(network_list, config['environment'], server.get('networks'))

            print "==> Creating Server {}".format(server_name)

            s = create_server(
                    name=server_name,
                    image=server_image,
                    flavor=server_flavor,
                    networks=server_networks,
                    keyname=keypair_name)

            cloud_servers.append(s)

            if 'block_storage' in server:
                block_name = '.'.join([server['name']+"-store",config['environment']])
                block_size = server['block_storage'].get('size', 100)
                block_type = server['block_storage'].get('type', 'SSD')
                block_mount = server['block_storage'].get('mount', '/dev/xvdb')

                print "-- Creating Block Storage {}".format(block_name)
                v = create_blockstorage(block_name, block_size, block_type)
                attach_list.append((s,v,block_mount))

            if 'load_balancers' in server:
                for lb in server['load_balancers']:
                    loadbalancer_name = lb.get('name')
                    loadbalancer_port = lb.get('port')
                    loadbalancer_enabled = lb.get('enabled', True)
                    lb_servers[loadbalancer_name]['nodes'].append(
                            {'server': s,
                            'port': loadbalancer_port,
                            'enabled': 'ENABLED' if loadbalancer_enabled else 'DISABLED' })

        ## wait 15min until all the servers are built and ACTIVE
        for s in cloud_servers:
            pyrax.utils.wait_until(s, "status", ["ACTIVE", "ERROR"],
                attempts=90, interval=10, verbose=True)

        # ZZzzz...
        abort = False

        for s in cloud_servers:
            if s.status != 'ACTIVE':
                print "** {} status is {} **".format(s.name, s.status)
                abort = True

        if abort:
            print "Aborting."
            sys.exit()

        ## Attach block storage to all severs that have them
        if attach_list:
            for (s,v,m) in attach_list:
                print "==> Attaching block storage to server {}".format(s.name)
                attach_blockstorage(s,v,m)

        ## Add Nodes to LB
        if 'load_balancers' in config:
            clb = pyrax.cloud_loadbalancers
            for lb_name, data in lb_servers.iteritems():
                print "==> Attaching nodes to load balancer {}".format(lb_name)
                nodes = [clb.Node(
                    address=s['server'].networks['private'][0],
                    port=s['port'],
                    condition=s['enabled']) for s in data['nodes']]

                for lb in data['loadbalancers']:
                    lb.add_nodes(nodes)

        loadbalancers = sum([ v['loadbalancers'] for k,v in lb_servers.iteritems()], [])
        return (cloud_servers, loadbalancers)

def print_report(servers, loadbalancers):

    ## list of unique network names across all servers
    network_names = list(set(sum([server.addresses.keys() for server in servers], [])))
    network_names.sort()

    server_table = PrettyTable(["Name", "Pasword", "accessIPv4"] + network_names )

    for s in servers:
        address_list = []
        for net in network_names:
            if net in s.addresses:
                address_list.append((n['addr'] for n in s.addresses[net]
                                    if n['version'] == 4).next() or '')
            else:
                address_list.append('')

        data = [s.name, s.adminPass, s.accessIPv4] + address_list
        server_table.add_row(data)

    lb_table = PrettyTable(["Name", "Port", "VIPs", "Source IPV4 public", "Source  IPV4 Servicenet"])

    for l in loadbalancers:
        data = [
            l.name,
            l.port,
            ', '.join([v.address for v in l.virtual_ips if '.' in v.address]),
            l.sourceAddresses['ipv4Public'],
            l.sourceAddresses['ipv4Servicenet']
        ]
        lb_table.add_row(data)

    if servers:
        print(server_table)

    if loadbalancers:
        print(lb_table)

def load_config(config_path):
    try:
        f = open (config_path, 'r')
        config = yaml.load(f)
    except:
        print "Error loading configuration file: {}".format(config_path)
        sys.exit()
    return config

def configure_pyrax(config):

    pyrax.set_setting("identity_type", "rackspace")
    pyrax.set_setting("region", config['rackspace_region'])

    credential_file = os.path.expanduser(config['rackspace_credentials'])
    pyrax.set_credential_file(credential_file)

    if not pyrax.identity.authenticated:
        print "Could not authenticate, is your ~/.rackspace_cloud_credentials correct?"
        sys.exit()

    print "Authenticated =", pyrax.identity.authenticated

def wait_for_rackconnect(server_list):

    print "-- Pausing for rackconnect to start"

    ## clone the list b/c we delete elements as they are ready
    servers = list(server_list)

    ## Set a 5 min timeout
    timeout = time.time() + 5*60

    while len(servers) > 0:
        for s in servers:
            s.get()

        if time.time() > timeout:
            print '**  rackconnect is taking a long time to provision **'
            for s in servers:
                print "  server: {}  automation_status: {}".format(
                    s.name, s.metadata['rackconnect_automation_status'] if 'rackconnect_automation_status' in s.metadata else '')
            break

        for s in servers:
            if 'rackconnect_automation_status' in s.metadata:
                if s.metadata['rackconnect_automation_status'] in ['DEPLOYED', 'UNPROCESSABLE', 'FAILED']:
                    print "   {} {}".format(s.name, s.metadata['rackconnect_automation_status'])
                    servers.remove(s)
        time.sleep(10)


def main():
    parser = argparse.ArgumentParser(
        description='Build rackspace cloud enviornments from a yaml document')
    parser.add_argument('--config', help='yaml description of the build', required=True)
    args = parser.parse_args()

    config_file = os.path.expanduser(args.config)
    config = load_config(config_file)
    configure_pyrax(config)
    servers,load_balancers = process_config(config)
    wait_for_rackconnect(servers)
    print_report(servers,load_balancers)

if __name__ == '__main__':
    main()


