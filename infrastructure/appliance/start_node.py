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

ORIGINAL_DIR = os.getcwd()
ROOT_DIR = os.path.join( os.path.abspath( os.path.dirname( os.path.realpath( __file__ ) ) ), '..', '..', '..' )
os.chdir( ROOT_DIR )
BEACH_CONFIG = os.path.join( ROOT_DIR, 'cloud', 'beach', 'lc_appliance.yaml' )

if __name__ == '__main__':
    if 0 == os.geteuid():
        print( "This script should not run as root." )
        sys.exit(1)

    parser = argparse.ArgumentParser( description = 'Start the LC appliance as a normal node.' )

    args = parser.parse_args()

    # Start the Beach node manager.
    os.system( 'screen -d -m python -m beach.hostmanager %s --log-level 10' % BEACH_CONFIG )

    # Start the reverse proxy for sensors.
    os.system( 'screen -d -m python %s -c %s -l 0.0.0.0:9090'% ( os.path.join( ROOT_DIR,
                                                                               'cloud',
                                                                               'standalone',
                                                                               'endpoint_proxy.py' ),
                                                                 BEACH_CONFIG, ) )

    print( "DONE STARTING APPLIANCE AS NORMAL NODE" )