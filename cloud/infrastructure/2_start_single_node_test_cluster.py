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

root = os.path.join( os.path.abspath( os.path.dirname( __file__ ) ), '..', '..' )

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
    os.system( 'screen -d -m python -m beach.hostmanager %s --log-level 10'% ( os.path.join( root,
                                                                                             'cloud',
                                                                                             'beach',
                                                                                             'lc_local.yaml' ), ) ) )

printStep( 'Starting the Beach dashboard on port 8080 (in a screen).',
    os.system( 'screen -d -m python -m beach.dashboard 8080 %s'% ( os.path.join( root,
                                                                                 'cloud',
                                                                                 'beach',
                                                                                 'lc_local.yaml' ), ) ) )

time.sleep( 2 )

printStep( 'Starting all actor in a Beach Patrol (in a screen).',
    os.system( 'screen -d -m python -m beach.patrol %s %s --realm hcp --set-scale 10' % 
        ( os.path.join( root,
                        'cloud',
                        'beach',
                        'lc_local.yaml' ),
          os.path.join( root,
                        'cloud',
                        'beach',
                        'full_lc_patrol.py' ) ) ) )

printStep( 'Starting the LIMA CHARLIE web interface on port 8888 (in a screen).',
    os.system( 'screen -d -m python %s %s 8888'% ( os.path.join( root,
                                                                 'cloud',
                                                                 'limacharlie',
                                                                 'app.py' ),
                                                   os.path.join( root,
                                                                 'cloud',
                                                                 'beach',
                                                                 'lc_local.yaml' ) ) ) )

printStep( 'Starting the BEACH REST interface on port 8000 (in a screen).',
    os.system( 'screen -d -m python -m beach.restbridge 8000 %s hcp'% ( os.path.join( root,
                                                                                      'cloud',
                                                                                      'beach',
                                                                                      'lc_local.yaml' ), ) ) )