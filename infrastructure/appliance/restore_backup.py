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
    parser = argparse.ArgumentParser( description = 'Restore a backup of configurations, organizations and crypto material.' )

    localIp = getLocalIp()

    parser.add_argument( '-s', '--source',
                         type = os.path.abspath,
                         dest = 'source',
                         required = True,
                         help = 'The file where to restore the backup from.' )

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

    try:
        backups = msgpack.unpackb( base64.b64decode( open( args.source, 'rb' ).read() ) )
    except:
        print( "! Failed to load backup file: %s" % traceback.format_exc() )
        sys.exit( 1 )

    try:
        for table, csv in backups.iteritems():
            with open( '_tmp_backup', 'wb' ) as f:
                f.write( csv )
            if 0 != os.system( "cqlsh %s -k hcp_analytics -e \"COPY %s FROM '_tmp_backup'\" > /dev/null" % ( localIp, table ) ):
                print( "! Failed to load backup for %s." % table )
                sys.exit( 1 )
    except:
        print( "! Failed to load backup: %s" % traceback.format_exc() )
        sys.exit( 1 )

    print( "FINISHED LOADING BACKUP" )