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

if __name__ == '__main__':
    if 0 == os.geteuid():
        print( "This script should not run as root." )
        sys.exit(1)

    parser = argparse.ArgumentParser( description = 'Start the LC appliance as an all in one cluster.' )

    args = parser.parse_args()

    ret = 0

    if 0 != os.system( './cloud/infrastructure/appliance/start_node.py' ):
    	print( "! Failed to start node." )
    	sys.exit(1)
    if 0 != os.system( './cloud/infrastructure/appliance/start_ui.py' ):
    	print( "! Failed to start ui." )
    	sys.exit(1)

    print( "DONE STARTING APPLIANCE AS ALL IN ONE CLUSTER" )