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
import traceback
import msgpack
import base64

ORIGINAL_DIR = os.getcwd()
ROOT_DIR = os.path.join( os.path.abspath( os.path.dirname( os.path.realpath( __file__ ) ) ), '..', '..', '..' )

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
    parser = argparse.ArgumentParser( description = 'Create a backup of configurations, organizations and crypto material.' )

    localIp = getLocalIp()

    parser.add_argument( '-d', '--destination',
                         type = os.path.abspath,
                         dest = 'destination',
                         required = True,
                         help = 'The file where to store the backup.' )

    parser.add_argument( '-i', '--interface',
                         type = str,
                         dest = 'interface',
                         required = False,
                         default = None,
                         help = 'The network interface to used as the main cluster interface.' )

    args = parser.parse_args()

    os.chdir( ROOT_DIR )

    if args.interface is not None:
        localIp = getIpv4ForIface( args.interface )
        if localIp is None:
            print( "! Failed to find network interface." )
            sys.exit( 1 )

    backups = {}
    try:
        for table in ( 'configs', 
                       'hcp_whitelist', 
                       'org_sensors', 
                       'org_membership', 
                       'sensor_tags', 
                       'user_info', 
                       'org_info',
                       'hbs_profiles',
                       'hbs_keys' ):
            if 0 != os.system( "cqlsh %s -k hcp_analytics -e \"COPY %s TO '_tmp_backup'\" > /dev/null" % ( localIp, table ) ):
                print( "! Failed to generate backup for %s." % table )
                sys.exit( 1 )
            with open( '_tmp_backup', 'rb' ) as f:
                backups[ table ] = f.read()

    except:
        print( "! Failed to generate backup: %s" % traceback.format_exc() )
        sys.exit( 1 )

    try:
        os.unlink( '_tmp_backup' )
    except:
        pass

    try:
        open( args.destination, 'wb' ).write( base64.b64encode( msgpack.packb( backups ) ) )
    except:
        print( "! Failed to write backup: %s" % traceback.format_exc() )
        sys.exit( 1 )

    print( "FINISHED BACKING UP TO %s" % args.destination )