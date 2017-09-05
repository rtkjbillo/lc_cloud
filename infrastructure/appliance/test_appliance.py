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

from beach.beach_api import Beach
import os
import sys
import argparse
import yaml
import socket
import time

try:
    from termcolor import colored
except:
    colored = None

ORIGINAL_DIR = os.getcwd()
ROOT_DIR = os.path.join( os.path.abspath( os.path.dirname( os.path.realpath( __file__ ) ) ), '..', '..', '..' )
os.chdir( ROOT_DIR )
BEACH_CONFIG = os.path.join( ROOT_DIR, 'cloud', 'beach', 'lc_appliance.yaml' )

BEACH = None

ON_FAILURE = []

def getLocalIp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def printStep( stepName ):
    hdr = '=' * ( ( 80 - len( stepName ) ) / 2 )
    if colored is not None:
        hdr = colored( hdr, 'green' )
        hdr = hdr + colored( stepName, 'yellow' ) + hdr
    print( '\n' + hdr )

def printSuccess( msg ):
    hdr = 'SUCCESS:'
    if colored is not None:
        hdr = colored( hdr, 'white', 'on_green' )
    print( hdr + ' ' + str( msg ) )

def printFailure( msg, isFatal = True ):
    global ON_FAILURE
    hdr = 'FAILED:'
    if colored is not None:
        hdr = colored( hdr, 'yellow', 'on_red' )
    print( hdr + ' ' + str( msg ) )
    if isFatal:
        fail = "APPLIANCE TEST FINISHED WITH FAILURE"
        if colored is not None:
            fail = colored( fail, 'red' )
        print( "\n" + fail + "\n" )

        ON_FAILURE.reverse()
        for func in ON_FAILURE:
            func()

        sys.exit(1)

def handleActorResponse( resp ):
    global args
    if args.is_display_responses:
        if resp.isSuccess:
            printSuccess( resp )
        else:
            printFailure( resp, isFatal = False )

if __name__ == '__main__':
    if 0 == os.geteuid():
        print( "This script should not run as root." )
        sys.exit(1)

    parser = argparse.ArgumentParser( description = 'Perform an appliance test.' )

    parser.add_argument( '--display-responses',
                         required = False,
                         default = False,
                         action = 'store_true',
                         dest = 'is_display_responses',
                         help = 'if specified, all actor responses will be displayed' )

    args = parser.parse_args()

    print( "Launching LimaCharlie Appliance Test" )

    printStep( 'BASE PLATFORM' )

    if 0 == os.system( 'cqlsh %s -e "desc keyspaces" > /dev/null 2>&1' % getLocalIp() ):
        printSuccess( "Cassandra is running." )
    else:
        printFailure( "Cassandra doesn't seem to be running." )

    BEACH = Beach( BEACH_CONFIG, 'hcp' )

    resp = BEACH.getClusterHealth()
    if 0 != len( resp ):
        printSuccess( 'Beach cluster is running with %d node(s).' % len( resp ) )
    else:
        printFailure( "Beach cluster doesn't seem to be running." )

    if 0 == os.system( 'ps -elf | grep -E ".*endpoint_proxy.*" | grep -v grep > /dev/null' ):
        printSuccess( 'Sensor proxy is running.' )
    else:
        printFailure( "Sensor proxy doesn't seem to be running." )

    if 0 == os.system( 'ps -elf | grep -E ".*beach\\.restbridge.*" | grep -v grep > /dev/null' ):
        printSuccess( 'Beach REST bridge is running.' )
    else:
        printFailure( "Beach REST bridge doesn't seem to be running, you can ignore this error if it is running from a different appliance.",
                      isFatal = False )

    if 0 == os.system( 'ps -elf | grep -E ".*/app\\.py.*" | grep -v grep > /dev/null' ):
        printSuccess( 'LC Web UI is running.' )
    else:
        printFailure( "LC Web UI doesn't seem to be running, you can ignore this error if it is running from a different appliance.",
                      isFatal = False )

    if 0 == os.system( 'ps -elf | grep -E ".*beach\\.dashboard.*" | grep -v grep > /dev/null' ):
        printSuccess( 'Beach dashboard is running.' )
    else:
        printFailure( "Beach dashboard doesn't seem to be running, you can ignore this error if it is running from a different appliance.",
                      isFatal = False )



    printStep( 'CORE ACTORS' )

    allActors = BEACH.getActorHandle( '', timeout = 60 )
    futures = allActors.requestFromAll( 'z', data = {} )
    isSuccess = True
    nActors = 0
    while not futures.isFinished():
        if not futures.waitForResults( timeout = 30 ):
            isSuccess = False
            break
        results = futures.getNewResults()
        for resp in results:
            handleActorResponse( resp )
            if not resp.isSuccess:
                isSuccess = False
                break
            nActors += 1
    allActors.close()

    if isSuccess:
        printSuccess( 'All actors (%d) responded with their z vars.' % nActors )
    else:
        printFailure( "Some actors failed to respond their z vars." )





    printStep( 'CREATE TEST IDENTS' )

    identManager = BEACH.getActorHandle( 'c2/identmanager', 
                                         ident = 'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903', 
                                         timeout = 30, 
                                         nRetries = 1 )
    resp = identManager.request( 'create_org', { 'name' : '_test_org', 'by' : 'appliance_test' } )
    handleActorResponse( resp )
    if resp.isSuccess:
        printSuccess( 'Test organization created: %s' % resp.data[ 'oid' ] )
    else:
        printFailure( "Couldn't create new organization for testing: %s." % resp.error )

    test_oid = resp.data[ 'oid' ]

    def _destroyTestOrg():
        resp = identManager.request( 'remove_org', { 'oid' : test_oid, 'by' : 'appliance_test' } )
        handleActorResponse( resp )
        if resp.isSuccess:
            printSuccess( 'Test organization removed.' )
        else:
            printFailure( "Couldn't remove test organization: %s." % resp.error, isFatal = False )

    ON_FAILURE.append( _destroyTestOrg )

    deploymentManager = BEACH.getActorHandle( 'c2/deploymentmanager', 
                                              ident = 'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903', 
                                              timeout = 30, 
                                              nRetries = 1 )
    resp = deploymentManager.request( 'deploy_org', { 'oid' : test_oid } )
    handleActorResponse( resp )
    if resp.isSuccess:
        printSuccess( 'Test organization deployed.' )
    else:
        printFailure( "Couldn't deploy test organization: %s." % resp.error )

    def _destroyTestUser():
        resp = identManager.request( 'delete_user', { 'email' : '_test_user@test.org', 'by' : 'appliance_test' } )
        handleActorResponse( resp )
        if resp.isSuccess and resp.data[ 'is_deleted' ]:
            printSuccess( 'Test user removed.' )
        else:
            printFailure( "Couldn't remove test user: %s." % resp, isFatal = False )

    ON_FAILURE.append( _destroyTestUser )

    resp = identManager.request( 'create_user', { 'email' : '_test_user@test.org', 
                                                  'by' : 'appliance_test',
                                                  'password' : 'letmein' } )
    handleActorResponse( resp )
    if resp.isSuccess and resp.data[ 'is_created' ]:
        printSuccess( 'Test user created: %s' % resp.data[ 'uid' ] )
    else:
        printFailure( "Couldn't create new user for testing: %s." % resp )

    test_uid = resp.data[ 'uid' ]

    resp = identManager.request( 'add_user_to_org', { 'email' : '_test_user@test.org', 
                                                      'by' : 'appliance_test',
                                                      'oid' : test_oid } )
    handleActorResponse( resp )
    if resp.isSuccess and resp.data[ 'is_added' ]:
        printSuccess( 'Test user added to test organization.' )
    else:
        printFailure( "Couldn't add test user to test organization: %s." % resp )

    def _removeUserFromOrg():
        resp = identManager.request( 'remove_user_from_org', { 'email' : '_test_user@test.org', 
                                                               'by' : 'appliance_test',
                                                               'oid' : test_oid } )
        handleActorResponse( resp )
        if resp.isSuccess and resp.data[ 'is_removed' ]:
            printSuccess( 'Test user removed from test organization.' )
        else:
            printFailure( "Couldn't remove test user from test organization: %s." % resp, isFatal = False )

    ON_FAILURE.append( _removeUserFromOrg )







    printStep( 'VERIFY IDENTS' )

    resp = identManager.request( 'get_org_info', { 'oid' : test_oid } )
    handleActorResponse( resp )
    if resp.isSuccess:
        printSuccess( 'Test org fetched.' )
    else:
        printFailure( "Couldn't fetch test org: %s." % resp.error )

    resp = identManager.request( 'get_user_info', { 'uid' : test_uid } )
    handleActorResponse( resp )
    if resp.isSuccess:
        printSuccess( 'Test user fetched.' )
    else:
        printFailure( "Couldn't fetch test user: %s." % resp.error )

    resp = identManager.request( 'get_org_members', { 'oid' : test_oid } )
    handleActorResponse( resp )
    if resp.isSuccess and 1 == len( resp.data[ 'orgs' ] ) and 1 == len( resp.data[ 'orgs' ].values() ):
        printSuccess( 'Test org fetched.' )
    else:
        printFailure( "Couldn't fetch test org: %s." % resp.error )




    printStep( 'TEARDOWN' )

    _removeUserFromOrg()
    _destroyTestUser()
    _destroyTestOrg()

    print( "\n" + colored( "APPLIANCE TEST FINISHED SUCCESSFULLY", 'green' ) + "\n" )