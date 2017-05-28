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

import gevent
import gevent.ssl
import gevent.socket
import gevent.pool
import gevent.event
from gevent.lock import Semaphore
from hcp.utils.hcp_helpers import AgentId
from hcp.utils.hcp_helpers import HcpOperations
from hcp.utils.hcp_helpers import HcpModuleId
from hcp.utils.rpcm import rpcm
from hcp.utils.rpcm import rList
from hcp.utils.rpcm import rSequence
from hcp.Symbols import Symbols
Symbols = Symbols()
import uuid
import traceback
import zlib
import struct
import msgpack
import hashlib
import random
import time

class DisconnectException( Exception ):
    pass

class VirtualSensor( gevent.Greenlet ):

    def __init__( self, cloudDest, cbReceiveMessage, orgId, installerId, platform, architecture, 
                  sensorId = None, enrollmentToken = None, 
                  cbDebugLog = None, cbEnrollment = None ):
        gevent.Greenlet.__init__( self )
        self.cbDebugLog = cbDebugLog
        self.cbReceiveMessage = cbReceiveMessage
        self.cbEnrollment = cbEnrollment
        try:
            self.destServer, self.destPort = cloudDest.split( ':' )
        except:
            self.destServer = cloudDest
            self.destPort = 443
        self.oid = uuid.UUID( str( orgId ) )
        self.iid = uuid.UUID( str( installerId ) )
        self.sid = sensorId
        self.arch = architecture
        self.plat = platform
        if self.sid is not None:
            self.sid = uuid.UUID( str( self.sid ) )
        self.enrollmentToken = enrollmentToken
        self.socket = None

        self.threads = gevent.pool.Group()
        self.stopEvent = gevent.event.Event()
        self.lock = Semaphore( 1 )
        self.connectedEvent = gevent.event.Event()

        self.r = rpcm( isHumanReadable = True, isDebug = self.log )
        self.r.loadSymbols( Symbols.lookups )

        self.hcpModules = []
        self.hbsProfileHash = ( "\x00" * 32 )

    def log( self, msg ):
        if self.cbDebugLog is not None:
            self.cbDebugLog( '%s => %s' % ( self.sid, msg ) )

    ###########################################################################
    #   SSL CONNECTION STUFF
    ###########################################################################
    def connect( self ):
        try:
            self.socket = gevent.ssl.wrap_socket( gevent.socket.socket( gevent.socket.AF_INET, 
                                                                 gevent.socket.SOCK_STREAM ), 
                                           cert_reqs = gevent.ssl.CERT_NONE )
            self.socket.connect( ( self.destServer, self.destPort ) )
            self.log( "Connected" )
            headers = rSequence()
            headers.addSequence( Symbols.base.HCP_IDENT, AgentId( ( self.oid, self.iid, self.sid, self.plat, self.arch ) ).toJson() )
            headers.addStringA( Symbols.base.HOST_NAME, hashlib.md5( str( self.sid ) ).hexdigest() )
            headers.addIpv4( Symbols.base.IP_ADDRESS, "%d.%d.%d.%d" % ( random.randint( 0, 254 ), 
                                                                        random.randint( 0, 254 ), 
                                                                        random.randint( 0, 254 ), 
                                                                        random.randint( 0, 254 ) ) )
            if self.enrollmentToken is not None:
                headers.addBuffer( Symbols.hcp.ENROLLMENT_TOKEN, self.enrollmentToken )
            self.sendFrame( HcpModuleId.HCP, [ headers ], timeout = 30, isNotHbs = True )
            self.log( "Handshake sent" )
            self.threads.add( gevent.spawn( self.recvThread ) )
            self.threads.add( gevent.spawn_later( 1, self.syncHcpThread ) )
            self.threads.add( gevent.spawn_later( 10, self.syncHbsThread ) )
            self.threads.add( gevent.spawn_later( 2, lambda: self.connectedEvent.set() ) )
            return True
        except:
            self.log( "Failed to connect over TLS: %s" % traceback.format_exc() )
            return False

    def disconnect( self ):
        self.log( "Disconnecting" )
        try:
            self.connectedEvent.clear()
            self.socket.close()
            self.threads.join( timeout = 5 )
            self.threads.kill( timeout = 1 )
        except:
            pass
        self.log( "Disconnected" )
        self.socket = None

    ###########################################################################
    #   THREADS
    ###########################################################################
    def recvThread( self ):
        while not self.stopEvent.wait( 0 ):
            try:
                moduleId, messages, nRawBytes = self.recvFrame( timeout = 60 * 60 )
            except:
                if self.stopEvent.wait( 0 ):
                    return
                raise
            if HcpModuleId.HCP == moduleId:
                # For now we assume a constant set of Modules for simplicity
                for message in messages:
                    if HcpOperations.LOAD_MODULE == message[ 'base.OPERATION' ]:
                        self.log( "Received HCP module load" )
                        self.hcpModules.append( ( message[ 'hcp.MODULE_ID' ], 
                                                  hashlib.sha256( message[ 'base.BINARY' ] ).digest() ) )
                    elif HcpOperations.SET_HCP_ID == message[ 'base.OPERATION' ]:
                        self.log( "Received enrollment" )
                        newId = AgentId( dict( message[ 'base.HCP_IDENT' ] ) )
                        self.sid = newId.sensor_id
                        self.enrollmentToken = message[ 'hcp.ENROLLMENT_TOKEN' ]
                        if self.cbEnrollment is not None:
                            self.cbEnrollment( self, newId, self.enrollmentToken )
            elif HcpModuleId.HBS == moduleId:
                for message in messages:
                    if 'notification.SYNC' == message.keys()[ 0 ]:
                        self.log( "Received HBS profile" )
                        self.hbsProfileHash = message[ 'notification.SYNC' ][ 'base.HASH' ]
                    else:
                        try:
                            self.cbReceiveMessage( self, message )
                        except:
                            self.log( "Error processing new messages: %s" % traceback.format_exc() )

    def syncHbsThread( self ):
        self.doHbsSync()
        self.threads.add( gevent.spawn_later( 60 * 5, self.syncHbsThread ) )

    def syncHcpThread( self ):
        self.doHcpSync()
        self.threads.add( gevent.spawn_later( 60 * 10, self.syncHcpThread ) )

    ###########################################################################
    #   SEND AND RECEIVE DATA STUFF
    ###########################################################################
    def recvData( self, size, timeout = None ):
        data = None
        timeout = gevent.Timeout( timeout )
        timeout.start()
        try:
            data = ''
            while size > len( data ):
                tmp = self.socket.recv( size - len( data ) )
                if not tmp:
                    raise DisconnectException( 'disconnect while receiving' )
                    break
                data += tmp
        except:
            raise
        finally:
            timeout.cancel()
        return data

    def recvFrame( self, timeout = None ):
        frameSize = struct.unpack( '>I', self.recvData( 4, timeout = timeout ) )[ 0 ]
        if (1024 * 1024 * 50) < frameSize:
            raise Exception( "frame size too large: %s" % frameSize )
        frame = self.recvData( frameSize, timeout = timeout )
        decompressedSize = struct.unpack( '>I', frame[ : 4 ] )[ 0 ]
        frame = zlib.decompress( frame[ 4 : ] )
        moduleId = struct.unpack( 'B', frame[ : 1 ] )[ 0 ]
        frame = frame[ 1 : ]
        self.r.setBuffer( frame )
        messages = self.r.deserialise( isList = True )
        return ( moduleId, messages, frameSize + 4 )

    def sendData( self, data, timeout = None ):
        timeout = gevent.Timeout( timeout )
        timeout.start()
        try:
            with self.lock:
                self.socket.sendall( data )
        except:
            raise DisconnectException( 'disconnect while sending' )
        finally:
            timeout.cancel()

    def sendFrame( self, moduleId, messages, timeout = None, isNotHbs = False ):
        msgList = rList()
        for msg in messages:
            if not isNotHbs:
                msg.values()[ 0 ][ 'value' ].addTimestamp( Symbols.base.TIMESTAMP, int( time.time() * 1000 ) )
            msgList.addSequence( Symbols.base.MESSAGE, msg )
        hcpData = struct.pack( 'B', moduleId ) + self.r.serialise( msgList )
        data = zlib.compress( hcpData )
        self.sendData( struct.pack( '>I', len( data ) ) + data, timeout = timeout )

    ###########################################################################
    #   HOUSE-KEEPING
    ###########################################################################
    def stop( self ):
        self.stopEvent.set()

    def doHcpSync( self ):
        moduleList = rList()
        for moduleId, moduleHash in self.hcpModules:
            moduleList.addSequence( Symbols.hcp.MODULE, rSequence().addInt8( Symbols.hcp.MODULE_ID, moduleId ) )
        self.log( "Sending HCP sync" )
        self.sendFrame( HcpModuleId.HCP, [ rSequence().addList( Symbols.hcp.MODULES, moduleList ) ], timeout = 30, isNotHbs = True )

    def doHbsSync( self ):
        self.log( "Sending HBS sync" )
        self.sendFrame( HcpModuleId.HBS, [ rSequence().addSequence( Symbols.notification.SYNC, 
                                                                    rSequence().addBuffer( Symbols.base.HASH, 
                                                                                           self.hbsProfileHash ) ) ], 30 )

    ###########################################################################
    #   MAIN
    ###########################################################################
    def _run( self ):
        try:
            self.log( "Starting virtual sensor: %s" % AgentId( ( self.oid, self.iid, self.sid, self.plat, self.arch ) ) )

            self.connect()

            self.stopEvent.wait()

            self.disconnect()
        except:
            self.log( "Exception:: %s" % traceback.format_exc() )
        self.log( "Sensor exited" )
