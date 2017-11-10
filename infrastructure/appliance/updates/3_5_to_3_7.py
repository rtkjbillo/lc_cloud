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

ORIGINAL_DIR = os.getcwd()
ROOT_DIR = os.path.join( os.path.abspath( os.path.dirname( os.path.realpath( __file__ ) ) ), '..', '..', '..', '..' )
os.chdir( ROOT_DIR )

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

    os.system( '''cqlsh %s -k hcp_analytics -e "ALTER TABLE hbs_profiles ADD tag varchar; COPY hbs_profiles ( aid, tag, cprofile, oprofile, hprofile ) TO '/tmp/hbs_profiles.txt' WITH HEADER=true AND DELIMITER='|' AND NULL=' '; DROP TABLE hbs_profiles; CREATE TABLE hbs_profiles( aid varchar, tag varchar, cprofile blob, oprofile varchar, hprofile varchar, PRIMARY KEY( aid, tag ) ) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400; COPY hbs_profiles (aid, tag, cprofile, oprofile, hprofile ) FROM '/tmp/hbs_profiles.txt' WITH HEADER=true AND DELIMITER='|' AND MAXBATCHSIZE=10;; CREATE TABLE stateful_states ( sid uuid, state_data blob, PRIMARY KEY( sid ) ) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;"''' % ( getLocalIp(), ) )

    print( "DONE UPGRADING TO 3.7" )