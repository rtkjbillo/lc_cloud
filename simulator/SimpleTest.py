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
import time
import signal
import msgpack
import base64
import sys
import argparse


parser = argparse.ArgumentParser( prog = 'Simulator' )
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

args = parser.parse_args()

SENSORS = gevent.pool.Group()

# Setting the signal handler to trigger the stop event
def _stop():
    global SENSORS
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

START_OFFSET = args.delay / ( NUM_SENSORS_OSX + NUM_SENSORS_WIN + NUM_SENSORS_LIN + len( CONF ) )

# Start existing sensors
for sensorInfo in CONF:
    aid = AgentId( str( sensorInfo[ 'aid' ] ) )
    token = sensorInfo[ 'token' ]

    SENSORS.start( VirtualSensor( 'hcp.limacharlie.io', 
                                  recvMessage, 
                                  aid.org_id, 
                                  aid.ins_id, 
                                  aid.platform, 
                                  aid.architecture,
                                  sensorId = aid.sensor_id,
                                  enrollmentToken = token,
                                  cbDebugLog = debugLog, 
                                  cbEnrollment = enrolled ) )
    gevent.sleep( START_OFFSET )

# Enroll new sensors
for i in range( 0, NUM_SENSORS_OSX + NUM_SENSORS_WIN + NUM_SENSORS_LIN ):
    if 0 != NUM_SENSORS_OSX:
        platform = AgentId.PLATFORM_MACOS
        NUM_SENSORS_OSX -= 1
    elif 0 != NUM_SENSORS_WIN:
        platform = AgentId.PLATFORM_WINDOWS
        NUM_SENSORS_WIN -= 1
    elif 0 != NUM_SENSORS_LIN:
        platform = AgentId.PLATFORM_LINUX
        NUM_SENSORS_LIN -= 1

    SENSORS.start( VirtualSensor( 'hcp.limacharlie.io', 
                                  recvMessage, 
                                  args.oid, 
                                  args.iid, 
                                  platform, 
                                  AgentId.ARCHITECTURE_X64,
                                  sensorId = None,
                                  enrollmentToken = None,
                                  cbDebugLog = debugLog, 
                                  cbEnrollment = enrolled ) )
    gevent.sleep( START_OFFSET )

print( "Waiting for all VirtualSensor to stop" )
SENSORS.join()