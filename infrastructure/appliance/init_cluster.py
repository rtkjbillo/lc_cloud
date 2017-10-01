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
import argparse
import socket
import sys
import netifaces

ORIGINAL_DIR = os.getcwd()
ROOT_DIR = os.path.join( os.path.abspath( os.path.dirname( os.path.realpath( __file__ ) ) ), '..', '..', '..' )
os.chdir( ROOT_DIR )

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
        sys.exit( 1 )

    localIp = getLocalIp()

    parser = argparse.ArgumentParser( description = 'Initialize this node as the first node of a new cluster.' )

    parser.add_argument( '-i', '--interface',
                         type = str,
                         dest = 'interface',
                         required = False,
                         default = None,
                         help = 'The network interface to use as main cluster interface.' )

    args = parser.parse_args()

    joinOpts = ''

    if args.interface is not None:
        localIp = getIpv4ForIface( args.interface )
        if localIp is None:
            print( "! Failed to find network interface." )
            sys.exit( 1 )
        joinOpts = ' --interface %s' % args.interface

    if 0 != os.system( 'python ./cloud/infrastructure/appliance/join_cluster.py -a %s%s' % ( localIp, joinOpts ) ):
        print( "! Failed to join cluster." )
        sys.exit( 1 )
    if 0 != os.system( 'cqlsh %s -f ./cloud/schema/scale_db.cql' % ( localIp, ) ):
        print( "! Failed to initialize db schema." )
        sys.exit( 1 )

    print( "FINISHED INITIALIZING CLUSTER" )