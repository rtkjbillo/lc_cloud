# Copyright 2015 refractionPOINT
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
import time
import argparse

root = os.path.join( os.path.abspath( os.path.dirname( __file__ ) ), '..', '..' )

parser = argparse.ArgumentParser()
parser.add_argument( '-b', '--beach',
                     type = str ,
                     required = False,
                     help = 'Specify the Beach cluster config file to use.',
                     dest = 'beach' )
parser.add_argument( '-p', '--patrol',
                     type = str ,
                     required = False,
                     help = 'Specify the patrol file to start.',
                     dest = 'patrol' )
arguments = parser.parse_args()

beachCluster = os.path.join( root,
                             'cloud',
                             'beach',
                             'lc_local.yaml' )

patrolFile = os.path.join( root,
                        'cloud',
                        'beach',
                        'core_lc_patrol.py' )

if arguments.beach is not None:
    beachCluster = os.path.abspath( arguments.beach )
    print( 'Using Beach cluster config: %s' % beachCluster )

if arguments.patrol is not None:
    patrolFile = arguments.patrol
    print( 'Using patrol file: %s' % patrolFile )

def printStep( step, *ret ):
    msg = '''
===============
Step: %s
Return Values: %s
===============

''' % ( step, str( ret ) )
    print( msg )
    if any( ret ):
        print( 'Stopping execution since this step failed.' )
        sys.exit(-1)

printStep( 'Starting the Beach host manager to make this host a one node cluster (in a screen).',
    os.system( 'screen -d -m python -m beach.hostmanager %s --log-level 10'% ( beachCluster, ) ) )

printStep( 'Starting the Beach dashboard on port 8080 (in a screen).',
    os.system( 'screen -d -m python -m beach.dashboard 8080 %s'% ( beachCluster, ) ) )

time.sleep( 2 )

printStep( 'Starting all actor in a Beach Patrol (in a screen).',
    os.system( 'screen -d -m python -m beach.patrol %s %s --realm hcp --set-scale 10' % 
        ( beachCluster,
          patrolFile ) ) )

printStep( 'Starting the LIMA CHARLIE web interface on port 8888 (in a screen).',
    os.system( 'screen -d -m python %s 8888'% ( os.path.join( root,
                                                              'cloud',
                                                              'limacharlie',
                                                              'app.py' ) ) ) )

printStep( 'Starting the BEACH REST interface on port 8889 (in a screen).',
    os.system( 'screen -d -m python -m beach.restbridge 8889 %s hcp'% ( beachCluster, ) ) )

printStep( 'Starting the LC Endpoint Proxy interface on port 9090 (in a screen).',
    os.system( 'screen -d -m python %s -c %s -l 0.0.0.0:9090'% ( os.path.join( root,
                                                                               'cloud',
                                                                               'standalone',
                                                                               'endpoint_proxy.py' ),
                                                                 beachCluster, ) ) )