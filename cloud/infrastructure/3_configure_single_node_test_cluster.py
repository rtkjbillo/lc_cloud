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
import hashlib

if os.geteuid() != 0:
    print( 'Please run me as root to setup this test, but don\'t ever do that in production!' )
    sys.exit(-1)

root = os.path.join( os.path.abspath( os.path.dirname( __file__ ) ), '..', '..' )
binaryPath = os.path.join( root, 'prebuilt_binaries' )
if 2 == len( sys.argv ):
    binaryPath = sys.argv[ 1 ]
    if not os.path.isdir( binaryPath ):
        print( "The path to the binaries is not valid: %s" % binaryPath )
        sys.exit(-1)

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

def execInBackend( script ):

    script = 'login %s\n%s' % ( os.path.join( root,
                                              'cloud',
                                              'beach',
                                              'sample_cli.conf' ),
                                script )

    with open( '_tmp_script', 'w' ) as f:
        f.write( script )

    ret = os.system( 'python %s --script _tmp_script' % ( os.path.join( root,
                                                                        'cloud',
                                                                        'beach',
                                                                        'hcp',
                                                                        'admin_cli.py' ), ) )
    os.unlink( '_tmp_script' )
    return ret


printStep( 'Adding enrollment rule to the cloud to enroll all sensors into the 1.1 range.',
    execInBackend( 'hcp_addEnrollmentRule -m ff.ff.ffffffff.fff.ff -o 1 -s 1' ) )

binaries = os.listdir( binaryPath )
for binary in binaries:
    if ( binary.startswith( 'hbs_' ) or binary.startswith( 'kernel_' ) ) and not binary.endswith( '.sig' ):
        printStep( 'Signing binary: %s' % binary,
            os.system( 'python %s -k %s -f %s -o %s' % ( os.path.join( root, 'tools', 'signing.py' ),
                                                         os.path.join( root, 'keys', 'root.priv.der' ),
                                                         os.path.join( root, 'prebuilt_binaries', binary ),
                                                         os.path.join( root, 'prebuilt_binaries', binary + '.sig' ) ) ) )

        if 'release' in binary:
            targetAgent = 'ff.ff.ffffffff.%s%s%s.ff'
            if 'x64' in binary:
                arch = 2
            elif 'x86' in binary:
                arch = 1
            if 'win' in binary:
                major = 1
                minor = 0
            elif 'osx' in binary:
                major = 2
                minor = 0
            elif 'ubuntu' in binary:
                major = 5
                minor = 4

            targetAgent = targetAgent % ( hex( arch )[ 2: ],
                                          hex( major )[ 2: ],
                                          hex( minor )[ 2: ] )

            with open( os.path.join( root, 'prebuilt_binaries', binary ) ) as f:
                h = hashlib.sha256( f.read() ).hexdigest()

            if binary.startswith( 'hbs_' ):
                printStep( 'Tasking HBS %s to all relevant sensors.' % binary,
                    execInBackend( '''hcp_addModule -i 1 -d %s -b %s -s %s
                                      hcp_addTasking -m %s -i 1 -s %s''' % ( binary,
                                                                             os.path.join( root, 'prebuilt_binaries', binary ),
                                                                             os.path.join( root, 'prebuilt_binaries', binary + '.sig' ),
                                                                             targetAgent,
                                                                             h ) ) )
            elif binary.startswith( 'kernel_' ):
                printStep( 'Tasking KERNEL %s to all relevant sensors.' % binary,
                           execInBackend( '''hcp_addModule -i 5 -d %s -b %s -s %s
                                             hcp_addTasking -m %s -i 5 -s %s''' % ( binary,
                                                                                    os.path.join( root, 'prebuilt_binaries', binary ),
                                                                                    os.path.join( root, 'prebuilt_binaries', binary + '.sig' ),
                                                                                    targetAgent,
                                                                                    h ) ) )

printStep( 'Setting HBS profile.',
           execInBackend( '''hbs_addProfile -m ff.ff.ffffffff.fff.ff -f %s''' % ( os.path.join( root,
                                                                                                'cloud',
                                                                                                'beach',
                                                                                                'production_hbs.profile' ) ) ) )
