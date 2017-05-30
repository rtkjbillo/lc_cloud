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

from gevent import monkey
monkey.patch_all()
import gevent.pool

from VirtualSensor import VirtualSensor
from hcp.utils.hcp_helpers import AgentId
from hcp.utils.rpcm import rpcm
from hcp.utils.rpcm import rList
from hcp.utils.rpcm import rSequence
from hcp.Symbols import Symbols
Symbols = Symbols()
import time
import signal
import msgpack
import base64
import sys
import argparse
import random
import string
import uuid
import hashlib


parser = argparse.ArgumentParser( prog = 'Simulator' )
parser.add_argument( 'cloud',
                     type = str,
                     help = 'where to reach the cloud' )
parser.add_argument( 'oid',
                     type = str,
                     help = 'the organization id virtual sensors are in' )
parser.add_argument( 'iid',
                     type = str,
                     help = 'the installer id for the virtual sensors' )
parser.add_argument( 'configFile',
                     type = str,
                     help = 'the main config file where virtual sensors are saved and loaded from' )
parser.add_argument( '--osx',
                     type = int,
                     required = False,
                     dest = 'n_osx',
                     default = 0,
                     help = 'the number of OSX virtual sensors to start' )
parser.add_argument( '--windows',
                     type = int,
                     required = False,
                     dest = 'n_win',
                     default = 0,
                     help = 'the number of Windows virtual sensors to start' )
parser.add_argument( '--linux',
                     type = int,
                     required = False,
                     dest = 'n_lin',
                     default = 0,
                     help = 'the number of Linux virtual sensors to start' )
parser.add_argument( '--delay',
                     type = int,
                     required = False,
                     dest = 'delay',
                     default = 10,
                     help = 'the number of seconds on which the virtual sensors start, spread evenly' )
parser.add_argument( '--with-constant-traffic',
                     required = False,
                     dest = 'with_constant_traffic',
                     default = False,
                     action = 'store_true',
                     help = 'generates simulated traffic for each sensor, at constant load, if specified' )
parser.add_argument( '--with-startup-traffic',
                     required = False,
                     dest = 'with_startup_traffic',
                     default = False,
                     action = 'store_true',
                     help = 'generates simulated traffic for each sensor, including initial startup spike, if specified' )

args = parser.parse_args()

SENSORS = gevent.pool.Group()
IS_STOP = False

# Setting the signal handler to trigger the stop event
def _stop():
    global SENSORS
    global IS_STOP
    IS_STOP = True
    print( "Signaling all VirtualSensor to stop" )
    for sensor in SENSORS:
        sensor.stop()
    print( "Signaled, waiting for stop")

global timeToStopEvent
gevent.signal( signal.SIGQUIT, _stop )
gevent.signal( signal.SIGINT, _stop )

SCALE_TEST_OID  = args.oid
SCALE_TEST_IID = args.iid
SCALE_TEST_FILE = args.configFile
NUM_SENSORS_OSX = args.n_osx
NUM_SENSORS_WIN = args.n_win
NUM_SENSORS_LIN = args.n_lin
CONF = []
try:
    with open( SCALE_TEST_FILE, 'rb' ) as f:
        CONF = msgpack.unpackb( f.read() )
        print( "Loaded %s sensors from conf" % len( CONF ) )
except:
    print( "Failed to read conf" )

def recvMessage( sensor, message ):
    print( "FROM %s GOT %s" % ( sensor, message ) )

def enrolled( sensor, newAgentId, enrollmentToken ):
    global CONF
    print( "ENROLLED %s @ %s WITH %s" % ( sensor, newAgentId, base64.b64encode( enrollmentToken ) ) )
    CONF.append( { 'aid' : str( newAgentId ), 'token' : enrollmentToken } )
    with open( SCALE_TEST_FILE, 'wb' ) as f:
        f.write( msgpack.packb( CONF ) )

def debugLog( msg ):
    print( "DBG:: %s" % str( msg ) )

TOTAL_SENSORS_EXPECTED = NUM_SENSORS_OSX + NUM_SENSORS_WIN + NUM_SENSORS_LIN + len( CONF )
if 0 != TOTAL_SENSORS_EXPECTED:
    START_OFFSET = ( args.delay / TOTAL_SENSORS_EXPECTED ) if TOTAL_SENSORS_EXPECTED != 0 else 0

def randomStringOf( n ):
    return ''.join( random.choice( string.ascii_lowercase ) for _ in range( n ) )

def randomHash():
    return hashlib.sha256( str( random.randint( 0, 65536 ) ) ).digest()

# Events to generate
def generateDnsEvent():
    while True:
        yield rSequence().addSequence( Symbols.notification.DNS_REQUEST, 
                                       rSequence().addInt32( Symbols.base.PROCESS_ID, random.randint( 0, 0xFFFFFFFF ) )
                                                  .addStringA( Symbols.base.DOMAIN_NAME, "%s.%s.com" % ( randomStringOf( 3 ), randomStringOf( 8 ) ) )
                                                  .addBuffer( Symbols.hbs.PARENT_ATOM, uuid.uuid4().bytes )
                                                  .addBuffer( Symbols.hbs.THIS_ATOM, uuid.uuid4().bytes )
                                                  .addIpv4( Symbols.base.IP_ADDRESS, "%d.%d.%d.%d" % ( random.randint( 0, 254 ), 
                                                                                                       random.randint( 0, 254 ), 
                                                                                                       random.randint( 0, 254 ), 
                                                                                                       random.randint( 0, 254 ) ) )
                                                  .addInt32( Symbols.base.MESSAGE_ID, random.randint( 0, 0xFFFF ) )
                                                  .addInt8( Symbols.base.DNS_TYPE, 1 ) )

def generateCodeIdentityEvent():
    while True:
        filePath = "c:\\windows\\%s" % randomStringOf( 10 )
        yield rSequence().addSequence( Symbols.notification.CODE_IDENTITY, 
                                       rSequence().addInt32( Symbols.base.PROCESS_ID, random.randint( 0, 0xFFFFFFFF ) )
                                                  .addStringA( Symbols.base.FILE_PATH, filePath )
                                                  .addBuffer( Symbols.hbs.PARENT_ATOM, uuid.uuid4().bytes )
                                                  .addBuffer( Symbols.hbs.THIS_ATOM, uuid.uuid4().bytes )
                                                  .addBuffer( Symbols.base.HASH, randomHash() )
                                                  .addInt8( Symbols.base.ERROR, 0 )
                                                  .addSequence( Symbols.base.SIGNATURE,
                                                                rSequence().addInt8( Symbols.base.FILE_CERT_IS_VERIFIED_GLOBAL, 0 )
                                                                           .addStringA( Symbols.base.FILE_PATH, filePath )
                                                                           .addInt8( Symbols.base.FILE_CERT_IS_VERIFIED_LOCAL, 0 )
                                                                           .addInt32( Symbols.base.CERT_CHAIN_STATUS, 124 )
                                                                           .addStringA( Symbols.base.CERT_ISSUER, "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Production PCA 2011" )
                                                                           .addStringA( Symbols.base.CERT_ISSUER, "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows" )
                                                                           .addInt8( Symbols.base.FILE_IS_SIGNED, 1 ) ) )

def generateNewProcessEvent():
    while True:
        parentId = random.randint( 0, 0xFFFFFFFF )
        yield rSequence().addSequence( Symbols.notification.NEW_PROCESS, 
                                       rSequence().addInt32( Symbols.base.PROCESS_ID, random.randint( 0, 0xFFFFFFFF ) )
                                                  .addStringA( Symbols.base.FILE_PATH, "c:\\program files\\%s" % randomStringOf( 8 ) )
                                                  .addStringA( Symbols.base.COMMAND_LINE, "%s" % randomStringOf( 15 ) )
                                                  .addStringA( Symbols.base.USER_NAME, randomStringOf( 8 ) )
                                                  .addInt32( Symbols.base.USER_ID, random.randint( 0, 64 ) )
                                                  .addBuffer( Symbols.hbs.PARENT_ATOM, uuid.uuid4().bytes )
                                                  .addBuffer( Symbols.hbs.THIS_ATOM, uuid.uuid4().bytes )
                                                  .addInt32( Symbols.base.PARENT_PROCESS_ID, parentId )
                                                  .addSequence( Symbols.base.PARENT, 
                                                                rSequence().addInt32( Symbols.base.PROCESS_ID, parentId )
                                                                           .addStringA( Symbols.base.FILE_PATH, "c:\\program files\\%s" % randomStringOf( 8 ) )
                                                                           .addStringA( Symbols.base.COMMAND_LINE, "%s" % randomStringOf( 15 ) )
                                                                           .addStringA( Symbols.base.USER_NAME, randomStringOf( 8 ) )
                                                                           .addInt32( Symbols.base.USER_ID, random.randint( 0, 64 ) )
                                                                           .addInt32( Symbols.base.PARENT_PROCESS_ID, parentId ) ) )

def generateTerminateProcessEvent():
    while True:
        yield rSequence().addSequence( Symbols.notification.TERMINATE_PROCESS, 
                                       rSequence().addInt32( Symbols.base.PROCESS_ID, random.randint( 0, 0xFFFFFFFF ) )
                                                  .addBuffer( Symbols.hbs.PARENT_ATOM, uuid.uuid4().bytes )
                                                  .addBuffer( Symbols.hbs.THIS_ATOM, uuid.uuid4().bytes )
                                                  .addInt32( Symbols.base.PARENT_PROCESS_ID, random.randint( 0, 0xFFFFFFFF ) ) )

def generateUserObservedEvent():
    while True:
        yield rSequence().addSequence( Symbols.notification.USER_OBSERVED, 
                                       rSequence().addStringA( Symbols.base.USER_NAME, randomStringOf( 8 ) )
                                                  .addBuffer( Symbols.hbs.PARENT_ATOM, uuid.uuid4().bytes )
                                                  .addBuffer( Symbols.hbs.THIS_ATOM, uuid.uuid4().bytes ) )

def generateNetworkSummaryEvent():
    while True:
        connections = rList()
        for _ in range( 0, random.randint( 0, 11 ) ):
            connections.addSequence( Symbols.notification.NEW_TCP4_CONNECTION,
                                     rSequence().addInt32( Symbols.base.PROCESS_ID, random.randint( 0, 0xFFFFFFFF ) )
                                                .addInt8( Symbols.base.IS_OUTGOING, random.randint( 0, 1 ) )
                                                .addBuffer( Symbols.hbs.PARENT_ATOM, uuid.uuid4().bytes )
                                                .addBuffer( Symbols.hbs.THIS_ATOM, uuid.uuid4().bytes )
                                                .addTimestamp( Symbols.base.TIMESTAMP, int( time.time() * 1000 ) )
                                                .addSequence( Symbols.base.DESTINATION, 
                                                              rSequence().addIpv4( Symbols.base.IP_ADDRESS, 
                                                                                   "%d.%d.%d.%d" % ( random.randint( 0, 254 ), 
                                                                                                     random.randint( 0, 254 ), 
                                                                                                     random.randint( 0, 254 ), 
                                                                                                     random.randint( 0, 254 ) ) )
                                                                         .addInt16( Symbols.base.PORT, random.randint( 0, 0xFFFF ) ) )
                                                .addSequence( Symbols.base.SOURCE, 
                                                              rSequence().addIpv4( Symbols.base.IP_ADDRESS, 
                                                                                   "%d.%d.%d.%d" % ( random.randint( 0, 254 ), 
                                                                                                     random.randint( 0, 254 ), 
                                                                                                     random.randint( 0, 254 ), 
                                                                                                     random.randint( 0, 254 ) ) )
                                                                         .addInt16( Symbols.base.PORT, random.randint( 0, 0xFFFF ) ) ) )
        yield rSequence().addSequence( Symbols.notification.NETWORK_SUMMARY, 
                                       rSequence().addBuffer( Symbols.hbs.PARENT_ATOM, uuid.uuid4().bytes )
                                                  .addBuffer( Symbols.hbs.THIS_ATOM, uuid.uuid4().bytes )
                                                  .addSequence( Symbols.base.PROCESS, next( generateNewProcessEvent() ) )
                                                  .addList( Symbols.base.NETWORK_ACTIVITY, connections ) )

# Start existing sensors
for sensorInfo in CONF:
    if IS_STOP: break
    aid = AgentId( str( sensorInfo[ 'aid' ] ) )
    token = sensorInfo[ 'token' ]

    virtSensor = VirtualSensor( args.cloud, 
                                recvMessage, 
                                aid.org_id, 
                                aid.ins_id, 
                                aid.platform, 
                                aid.architecture,
                                sensorId = aid.sensor_id,
                                enrollmentToken = token,
                                cbDebugLog = debugLog, 
                                cbEnrollment = enrolled )
    SENSORS.start( virtSensor )

    if args.with_startup_traffic:
        virtSensor.scheduleEvent( 1, generateCodeIdentityEvent(), plusOrMinusNSeconds = 2, upToNEvents = 200 )
        virtSensor.scheduleEvent( 5, generateCodeIdentityEvent(), plusOrMinusNSeconds = 2, upToNEvents = 500 )
        virtSensor.scheduleEvent( 120, generateCodeIdentityEvent(), plusOrMinusNSeconds = 20, upToNEvents = 5000 )
    if args.with_constant_traffic or args.with_startup_traffic:
        virtSensor.scheduleEvent( 20, generateDnsEvent(), plusOrMinusNSeconds = 5 )
        virtSensor.scheduleEvent( 50, generateNewProcessEvent(), plusOrMinusNSeconds = 20 )
        virtSensor.scheduleEvent( 50, generateTerminateProcessEvent(), plusOrMinusNSeconds = 20 )
        virtSensor.scheduleEvent( 100, generateNetworkSummaryEvent(), plusOrMinusNSeconds = 40 )
        virtSensor.scheduleEvent( 60, generateUserObservedEvent(), plusOrMinusNSeconds = 600, upToNEvents = 10 )

    gevent.sleep( START_OFFSET )

# Enroll new sensors
for i in range( 0, NUM_SENSORS_OSX + NUM_SENSORS_WIN + NUM_SENSORS_LIN ):
    if IS_STOP: break
    if 0 != NUM_SENSORS_OSX:
        platform = AgentId.PLATFORM_MACOS
        NUM_SENSORS_OSX -= 1
    elif 0 != NUM_SENSORS_WIN:
        platform = AgentId.PLATFORM_WINDOWS
        NUM_SENSORS_WIN -= 1
    elif 0 != NUM_SENSORS_LIN:
        platform = AgentId.PLATFORM_LINUX
        NUM_SENSORS_LIN -= 1

    virtSensor = VirtualSensor( args.cloud, 
                                recvMessage, 
                                args.oid, 
                                args.iid, 
                                platform, 
                                AgentId.ARCHITECTURE_X64,
                                sensorId = None,
                                enrollmentToken = None,
                                cbDebugLog = debugLog, 
                                cbEnrollment = enrolled )
    SENSORS.start( virtSensor )

    if args.with_startup_traffic:
        virtSensor.scheduleEvent( 1, generateCodeIdentityEvent(), plusOrMinusNSeconds = 2, upToNEvents = 200 )
        virtSensor.scheduleEvent( 5, generateCodeIdentityEvent(), plusOrMinusNSeconds = 2, upToNEvents = 500 )
        virtSensor.scheduleEvent( 120, generateCodeIdentityEvent(), plusOrMinusNSeconds = 20, upToNEvents = 5000 )
    if args.with_constant_traffic or args.with_startup_traffic:
        virtSensor.scheduleEvent( 20, generateDnsEvent(), plusOrMinusNSeconds = 5 )
        virtSensor.scheduleEvent( 50, generateNewProcessEvent(), plusOrMinusNSeconds = 20 )
        virtSensor.scheduleEvent( 50, generateTerminateProcessEvent(), plusOrMinusNSeconds = 20 )
        virtSensor.scheduleEvent( 100, generateNetworkSummaryEvent(), plusOrMinusNSeconds = 40 )
        virtSensor.scheduleEvent( 60, generateUserObservedEvent(), plusOrMinusNSeconds = 600, upToNEvents = 10 )

    gevent.sleep( START_OFFSET )

print( "Waiting for all VirtualSensor to stop" )
SENSORS.join()