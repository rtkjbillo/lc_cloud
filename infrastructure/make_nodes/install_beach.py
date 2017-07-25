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

if os.geteuid() != 0:
    print( 'Please run me as root to setup.' )
    sys.exit(-1)

root = os.path.join( os.path.abspath( os.path.dirname( __file__ ) ), '..', '..' )
originalDir = os.getcwd()
os.chdir( root )

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

printStep( 'Updating repo and upgrading existing components.',
    os.system( 'apt-get update -y' ),
    os.system( 'apt-get upgrade -y' ) )

printStep( 'Installing some basic packages required for Beach (mainly).',
    os.system( 'apt-get install libssl-dev openssl python-pip python-dev debconf-utils python-m2crypto python-pexpect -y' ) )

print( 'Download prefixtree (expected to fail).' )
os.system( 'pip download prefixtree' )

printStep( 'Installing prefixtree.',
    os.system( 'pip install --upgrade pip' ),
    os.system( 'pip install distribute' ),
    os.system( 'tar xzf *prefixtree*.tar.gz' ),
    os.system( 'rm *prefixtree*.tar.gz' ),
    os.system( 'sed -i \'s/from distribute_setup import use_setuptools//g\' *prefixtree*/setup.py' ),
    os.system( 'sed -i \'s/use_setuptools()//g\' *prefixtree*/setup.py' ),
    os.system( 'cd *prefixtree*; python ./setup.py install; cd ..' ) )

printStep( 'Installing Beach.',
    os.system( 'pip install beach' ) )
