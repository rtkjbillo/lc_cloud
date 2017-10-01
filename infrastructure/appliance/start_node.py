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
import socket
import time

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

if __name__ == '__main__':
    if 0 == os.geteuid():
        print( "This script should not run as root." )
        sys.exit(1)

    parser = argparse.ArgumentParser( description = 'Start the LC appliance as a normal node.' )

    args = parser.parse_args()

    # Make sure Cassandra is running.
    waits = 0
    while True:
        if 0 == os.system( 'cqlsh %s -e "desc keyspaces" > /dev/null 2>&1' % getLocalIp() ):
            print( "Cassandra is running." )
            break
        if 300 < waits:
            print( "Looks like Cassandra is not coming online, check into it (/var/log/cassandra/system.log)." )
            sys.exit( 1 )
        if 0 == waits % 5:
            print( "Waiting for Cassandra to come online." )
        time.sleep( 1 )
        waits += 1

    # Start the Beach node manager.
    if 0 != os.system( 'screen -S beach -d -m python -m beach.hostmanager %s --log-level 10' % BEACH_CONFIG ):
        print( "! Failed to start Beach hostmanager." )
        sys.exit(1)

    # Start the reverse proxy for sensors.
    if 0 != os.system( 'screen -S proxy -d -m python %s -c %s -l 0.0.0.0:9090'% ( os.path.join( ROOT_DIR,
                                                                                                'cloud',
                                                                                                'standalone',
                                                                                                'endpoint_proxy.py' ),
                                                                                  BEACH_CONFIG, ) ):
        print( "! Failed to start proxy." )
        sys.exit(1)

    print( "DONE STARTING APPLIANCE AS NORMAL NODE" )