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

ORIGINAL_DIR = os.getcwd()
ROOT_DIR = os.path.join( os.path.abspath( os.path.dirname( os.path.realpath( __file__ ) ) ), '..', '..', '..' )
os.chdir( ROOT_DIR )

def getLocalIp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

if __name__ == '__main__':
    if 0 != os.geteuid():
        print( "This script needs to be executing as root, use sudo." )
        sys.exit(1)

    localIp = getLocalIp()

    parser = argparse.ArgumentParser( description = 'Initialize this node as the first node of a new cluster.' )

    args = parser.parse_args()

    os.system( 'python ./cloud/infrastructure/appliance/join_cluster.py -a %s' % localIp )
    os.system( 'cqlsh %s -f ./cloud/schema/scale_db.cql' % ( localIp, ) )

    print( "FINISHED INITIALIZING CLUSTER" )