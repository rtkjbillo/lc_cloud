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

ORIGINAL_DIR = os.getcwd()
ROOT_DIR = os.path.join( os.path.abspath( os.path.dirname( os.path.realpath( __file__ ) ) ), '..', '..', '..' )
os.chdir( ROOT_DIR )

if __name__ == '__main__':
    if 0 != os.geteuid():
        print( "This script needs to be executing as root, use sudo." )
        sys.exit(1)

    parser = argparse.ArgumentParser( description = 'Join this node to an existing cluster.' )

    parser.add_argument( '-a', '--address',
                         type = str,
                         required = True,
                         dest = 'address',
                         action = 'append',
                         default = [],
                         help = 'The IP address of an existing node to join, this can be repeated to seed with multiple nodes.' )

    args = parser.parse_args()

    # Read the Cassandra config.
    with open( '/etc/cassandra/cassandra.yaml', 'rb' ) as f:
        cassConf = yaml.load( f.read() )

    # Add the seed node.
    cassConf[ 'seed_provider' ][ 0 ][ 'parameters' ][ 0 ][ 'seeds' ] = ','.join( args.address )

    # Write the custom config where Cassandra expects it.
    with open( '/etc/cassandra/cassandra.yaml', 'wb' ) as f:
        f.write( yaml.dump( cassConf ) )

    # Similarly we use lc_local.yaml as a template.
    with open( './cloud/beach/lc_local.yaml', 'rb' ) as f:
        beachConf = yaml.load( f.read() )

    beachConf[ 'seed_nodes' ] = args.address

    # And we use lc_appliance.yaml for our config.
    with open( './cloud/beach/lc_appliance.yaml', 'wb' ) as f:
        f.write( yaml.dump( beachConf ) )

    os.system( 'service cassandra restart' )
    time.sleep( 20 )

    print( "FINISHED JOINING CLUSTER AT: %s" % ( str( args.address ), ) )