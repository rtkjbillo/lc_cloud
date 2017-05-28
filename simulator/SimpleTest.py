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

if 5 != len( sys.argv ):
    print( "Usage: <OID> <IID> <STATE_FILE> <NUM_SENSORS>" )
    sys.exit( -1 )

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

SCALE_TEST_OID  = sys.argv[ 1 ]
SCALE_TEST_IID = sys.argv[ 2 ]
SCALE_TEST_FILE = sys.argv[ 3 ]
NUM_SENSORS = int( sys.argv[ 4 ] )
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
    CONF.append( { 'sid' : str( newAgentId.sensor_id ), 'token' : enrollmentToken } )
    with open( SCALE_TEST_FILE, 'wb' ) as f:
        f.write( msgpack.packb( CONF ) )

def debugLog( msg ):
    print( "DBG:: %s" % str( msg ) )

for i in range( 0, NUM_SENSORS ):
    if i < len( CONF ):
        existing = CONF[ i ]
        sid = str( existing[ 'sid' ] )
        token = existing[ 'token' ]
    else:
        sid = None
        token = None

    SENSORS.start( VirtualSensor( 'hcp.limacharlie.io', 
                                  recvMessage, 
                                  SCALE_TEST_OID, 
                                  SCALE_TEST_IID, 
                                  AgentId.PLATFORM_MACOS, 
                                  AgentId.ARCHITECTURE_X64,
                                  sensorId = sid,
                                  enrollmentToken = token,
                                  cbDebugLog = debugLog, 
                                  cbEnrollment = enrolled ) )

print( "Waiting for all VirtualSensor to stop" )
SENSORS.join()