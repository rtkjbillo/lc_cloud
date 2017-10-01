#! /usr/bin/python
# Copyright 2017 Google, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import argparse
import yaml
import time
import socket
import netifaces
from sets import Set

ORIGINAL_DIR = os.getcwd()
ROOT_DIR = os.path.join( os.path.abspath( os.path.dirname( os.path.realpath( __file__ ) ) ), '..', '..', '..' )
os.chdir( ROOT_DIR )
BEACH_CONFIG = os.path.join( ROOT_DIR, 'cloud', 'beach', 'lc_appliance.yaml' )

def getLocalIp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def getIpv4ForIface( iface ):
    ip = None
    try:
        ip = netifaces.ifaddresses( iface )[ netifaces.AF_INET ][ 0 ][ 'addr' ]
    except:
        pass
    return ip

if __name__ == '__main__':
    if 0 != os.geteuid():
        print( "This script needs to be executing as root, use sudo." )
        sys.exit(1)

    parser = argparse.ArgumentParser( description = 'Join this node to an existing cluster.' )

    parser.add_argument( '-a', '--address',
                         type = str,
                         dest = 'address',
                         action = 'append',
                         default = [],
                         help = 'The IP address of an existing node to join, this can be repeated to seed with multiple nodes.' )

    parser.add_argument( '--no-restart',
                         dest = 'isNoRestart',
                         action = 'store_true',
                         default = False,
                         help = 'Do not restart subsystems if this flag is present.' )

    parser.add_argument( '-i', '--interface',
                         type = str,
                         dest = 'interface',
                         required = False,
                         default = None,
                         help = 'The network interface to use as main cluster interface.' )

    args = parser.parse_args()

    localIp = getLocalIp()

    if args.interface is not None:
        localIp = getIpv4ForIface( args.interface )
        if localIp is None:
            print( "! Failed to find network interface." )
            sys.exit( 1 )

    # Always add ourselves to this list.
    addresses = Set( args.address )
    addresses.add( getLocalIp() )
    addresses = list( addresses )

    # Read the Cassandra config.
    with open( '/etc/cassandra/cassandra.yaml', 'rb' ) as f:
        cassConf = yaml.load( f.read() )

    # Add the seed node.
    cassConf[ 'seed_provider' ][ 0 ][ 'parameters' ][ 0 ][ 'seeds' ] = ','.join( addresses )

    # If an interface was specified, set it for Cassandra.
    if args.interface is not None:
        cassConf[ 'listen_interface' ] = args.interface
        cassConf[ 'rpc_interface' ] = args.interface


    # Write the custom config where Cassandra expects it.
    with open( '/etc/cassandra/cassandra.yaml', 'wb' ) as f:
        f.write( yaml.dump( cassConf ) )

    # Similarly we use lc_local.yaml as a template.
    with open( './cloud/beach/lc_local.yaml', 'rb' ) as f:
        beachConf = yaml.load( f.read() )

    beachConf[ 'seed_nodes' ] = addresses

    # If an interface was specified, set it for Beach.
    if args.interface is not None:
        beachConf[ 'interface' ] = args.interface

    # And we use lc_appliance.yaml for our config.
    with open( BEACH_CONFIG, 'wb' ) as f:
        f.write( yaml.dump( beachConf ) )

    # Restart Cassandra to use new seeds.
    if not args.isNoRestart:
        os.system( 'service cassandra restart' )
        print( "...restarting cassandra, standby." )
        # Make sure Cassandra is running.
        waits = 0
        while True:
            if 0 == os.system( 'cqlsh %s -e "desc keyspaces" > /dev/null 2>&1' % localIp ):
                print( "Cassandra is running." )
                break
            if 300 < waits:
                print( "Looks like Cassandra is not coming online, check into it (/var/log/cassandra/system.log)." )
                sys.exit( 1 )
            if 0 == waits % 5:
                print( "Waiting for Cassandra to come online." )
            time.sleep( 1 )
            waits += 1

    # We save a yaml file with the seeds to be optionally used by other components.
    with open( '../lc_appliance_cluster.yaml', 'wb' ) as f:
        f.write( yaml.dump( { 'seeds' : addresses } ) )

    print( "FINISHED JOINING CLUSTER AT: %s" % ( str( addresses ), ) )