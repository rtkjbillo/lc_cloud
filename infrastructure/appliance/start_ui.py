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

ORIGINAL_DIR = os.getcwd()
ROOT_DIR = os.path.join( os.path.abspath( os.path.dirname( os.path.realpath( __file__ ) ) ), '..', '..', '..' )
os.chdir( ROOT_DIR )
BEACH_CONFIG = os.path.join( ROOT_DIR, 'cloud', 'beach', 'lc_appliance.yaml' )
CORE_PATROL = os.path.join( ROOT_DIR, 'cloud', 'beach', 'appliance_lc_patrol.py' )

if __name__ == '__main__':
    if 0 == os.geteuid():
        print( "This script should not run as root." )
        sys.exit(1)

    parser = argparse.ArgumentParser( description = 'Start the LC UI component on this appliance.' )

    args = parser.parse_args()

    os.system( 'screen -S dashboard_beach -d -m python -m beach.dashboard 8080 %s'% ( BEACH_CONFIG, ) )

    os.system( 'screen -S patrol -d -m python -m beach.patrol %s %s --realm hcp --set-scale 10' % ( BEACH_CONFIG,
                                                                                                    CORE_PATROL ) )

    os.system( 'screen -S web -d -m python %s 8888'% ( os.path.join( ROOT_DIR,
                                                                     'cloud',
                                                                     'limacharlie',
                                                                     'app.py' ) ) )

    os.system( 'screen -S rest -d -m python -m beach.restbridge 8889 %s hcp'% ( BEACH_CONFIG, ) )

    print( "DONE STARTING APPLIANCE AS NORMAL NODE WITH UI" )