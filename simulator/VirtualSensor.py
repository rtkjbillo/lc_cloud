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
        self._cbDebugLog = cbDebugLog
        self._cbReceiveMessage = cbReceiveMessage
        self._cbEnrollment = cbEnrollment
        try:
            self._destServer, self._destPort = cloudDest.split( ':' )
        except:
            self._destServer = cloudDest
            self._destPort = 443
        self._oid = uuid.UUID( str( orgId ) )
        self._iid = uuid.UUID( str( installerId ) )
        self._sid = sensorId
        self._arch = architecture
        self._plat = platform
        if self._sid is not None:
            self._sid = uuid.UUID( str( self._sid ) )
        self._enrollmentToken = enrollmentToken
        self._socket = None

        self._threads = gevent.pool.Group()
        self._stopEvent = gevent.event.Event()
        self._lock = Semaphore( 1 )
        self._connectedEvent = gevent.event.Event()

        self._r = rpcm( isHumanReadable = True, isDebug = self._log )
        self._r.loadSymbols( Symbols.lookups )

        self._hcpModules = []
        self._hbsProfileHash = ( "\x00" * 32 )

    def _log( self, msg ):
        if self._cbDebugLog is not None:
            self._cbDebugLog( '%s => %s' % ( self._sid, msg ) )

    ###########################################################################
    #   SSL CONNECTION STUFF
    ###########################################################################
    def _connect( self ):
        try:
            self._socket = gevent.ssl.wrap_socket( gevent.socket.socket( gevent.socket.AF_INET, 
                                                                 gevent.socket.SOCK_STREAM ), 
                                           cert_reqs = gevent.ssl.CERT_NONE )
            self._socket.connect( ( self._destServer, self._destPort ) )
            self._log( "Connected" )
            headers = rSequence()
            headers.addSequence( Symbols.base.HCP_IDENT, AgentId( ( self._oid, self._iid, self._sid, self._plat, self._arch ) ).toJson() )
            headers.addStringA( Symbols.base.HOST_NAME, hashlib.md5( str( self._sid ) ).hexdigest() )
            headers.addIpv4( Symbols.base.IP_ADDRESS, "%d.%d.%d.%d" % ( random.randint( 0, 254 ), 
                                                                        random.randint( 0, 254 ), 
                                                                        random.randint( 0, 254 ), 
                                                                        random.randint( 0, 254 ) ) )
            if self._enrollmentToken is not None:
                headers.addBuffer( Symbols.hcp.ENROLLMENT_TOKEN, self._enrollmentToken )
            self._sendFrame( HcpModuleId.HCP, [ headers ], timeout = 30, isNotHbs = True )
            self._log( "Handshake sent" )
            self._threads.add( gevent.spawn( self._recvThread ) )
            self._threads.add( gevent.spawn_later( 1, self._syncHcpThread ) )
            self._threads.add( gevent.spawn_later( 10, self._syncHbsThread ) )
            self._threads.add( gevent.spawn_later( 2, lambda: self._connectedEvent.set() ) )
            return True
        except:
            self._log( "Failed to connect over TLS: %s" % traceback.format_exc() )
            return False

    def _disconnect( self ):
        self._log( "Disconnecting" )
        try:
            self._connectedEvent.clear()
            self._socket.close()
            self._threads.join( timeout = 5 )
            self._threads.kill( timeout = 1 )
        except:
            pass
        self._log( "Disconnected" )
        self._socket = None

    ###########################################################################
    #   THREADS
    ###########################################################################
    def _recvThread( self ):
        while not self._stopEvent.wait( 0 ):
            try:
                moduleId, messages, nRawBytes = self._recvFrame( timeout = 60 * 60 )
            except:
                if self._stopEvent.wait( 0 ):
                    return
                raise
            if HcpModuleId.HCP == moduleId:
                # For now we assume a constant set of Modules for simplicity
                for message in messages:
                    if HcpOperations.LOAD_MODULE == message[ 'base.OPERATION' ]:
                        self._log( "Received HCP module load" )
                        self._hcpModules.append( ( message[ 'hcp.MODULE_ID' ], 
                                                   hashlib.sha256( message[ 'base.BINARY' ] ).digest() ) )
                    elif HcpOperations.SET_HCP_ID == message[ 'base.OPERATION' ]:
                        self._log( "Received enrollment" )
                        newId = AgentId( dict( message[ 'base.HCP_IDENT' ] ) )
                        self._sid = newId.sensor_id
                        self._enrollmentToken = message[ 'hcp.ENROLLMENT_TOKEN' ]
                        if self._cbEnrollment is not None:
                            self._cbEnrollment( self, newId, self._enrollmentToken )
            elif HcpModuleId.HBS == moduleId:
                for message in messages:
                    if 'notification.SYNC' == message.keys()[ 0 ]:
                        self._log( "Received HBS profile" )
                        self._hbsProfileHash = message[ 'notification.SYNC' ][ 'base.HASH' ]
                    else:
                        try:
                            self._cbReceiveMessage( self, message )
                        except:
                            self._log( "Error processing new messages: %s" % traceback.format_exc() )

    def _syncHbsThread( self ):
        self._doHbsSync()
        self._threads.add( gevent.spawn_later( 60 * 5, self._syncHbsThread ) )

    def _syncHcpThread( self ):
        self._doHcpSync()
        self._threads.add( gevent.spawn_later( 60 * 10, self._syncHcpThread ) )

    ###########################################################################
    #   SEND AND RECEIVE DATA STUFF
    ###########################################################################
    def _recvData( self, size, timeout = None ):
        data = None
        timeout = gevent.Timeout( timeout )
        timeout.start()
        try:
            data = ''
            while size > len( data ):
                tmp = self._socket.recv( size - len( data ) )
                if not tmp:
                    raise DisconnectException( 'disconnect while receiving' )
                    break
                data += tmp
        except:
            raise
        finally:
            timeout.cancel()
        return data

    def _recvFrame( self, timeout = None ):
        frameSize = struct.unpack( '>I', self._recvData( 4, timeout = timeout ) )[ 0 ]
        if (1024 * 1024 * 50) < frameSize:
            raise Exception( "frame size too large: %s" % frameSize )
        frame = self._recvData( frameSize, timeout = timeout )
        decompressedSize = struct.unpack( '>I', frame[ : 4 ] )[ 0 ]
        frame = zlib.decompress( frame[ 4 : ] )
        moduleId = struct.unpack( 'B', frame[ : 1 ] )[ 0 ]
        frame = frame[ 1 : ]
        self._r.setBuffer( frame )
        messages = self._r.deserialise( isList = True )
        return ( moduleId, messages, frameSize + 4 )

    def _sendData( self, data, timeout = None ):
        timeout = gevent.Timeout( timeout )
        timeout.start()
        try:
            with self._lock:
                self._socket.sendall( data )
        except:
            raise DisconnectException( 'disconnect while sending' )
        finally:
            timeout.cancel()

    def _sendFrame( self, moduleId, messages, timeout = None, isNotHbs = False ):
        msgList = rList()
        for msg in messages:
            if not isNotHbs:
                msg.values()[ 0 ][ 'value' ].addTimestamp( Symbols.base.TIMESTAMP, int( time.time() * 1000 ) )
            msgList.addSequence( Symbols.base.MESSAGE, msg )
        hcpData = struct.pack( 'B', moduleId ) + self._r.serialise( msgList )
        data = zlib.compress( hcpData )
        self._sendData( struct.pack( '>I', len( data ) ) + data, timeout = timeout )

    ###########################################################################
    #   HOUSE-KEEPING
    ###########################################################################
    def _doHcpSync( self ):
        moduleList = rList()
        for moduleId, moduleHash in self._hcpModules:
            moduleList.addSequence( Symbols.hcp.MODULE, rSequence().addInt8( Symbols.hcp.MODULE_ID, moduleId )
                                                                   .addBuffer( Symbols.base.HASH, moduleHash ) )
        self._log( "Sending HCP sync" )
        self._sendFrame( HcpModuleId.HCP, [ rSequence().addList( Symbols.hcp.MODULES, moduleList ) ], timeout = 30, isNotHbs = True )

    def _doHbsSync( self ):
        self._log( "Sending HBS sync" )
        self._sendFrame( HcpModuleId.HBS, [ rSequence().addSequence( Symbols.notification.SYNC, 
                                                                    rSequence().addBuffer( Symbols.base.HASH, 
                                                                                           self._hbsProfileHash ) ) ], 30 )

    def _generateEvent( self, everyNSeconds, eventGenerator, plusOrMinusNSeconds, upToNEvents ):
        if self._connectedEvent.wait( 0 ):
            if upToNEvents is None or 0 != upToNEvents:
                if upToNEvents is not None:
                    upToNEvents -= 1
                try:
                    messages = next( eventGenerator )
                except StopIteration:
                    self._log( "Scheduled event generator failed to generate, ignoring it in the future." )
                    return
            else:
                return

            if type( messages ) not in ( tuple, list ):
                messages = ( messages, )

            self._sendFrame( HcpModuleId.HBS, messages, timeout = 30 )

        if not self._stopEvent.wait( 0 ):
            nextEvent = everyNSeconds
            if 0 != plusOrMinusNSeconds:
                nextEvent += random.randint( -plusOrMinusNSeconds, plusOrMinusNSeconds )
            if 0 > nextEvent:
                nextEvent = 0
            self._threads.add( gevent.spawn_later( nextEvent, self._generateEvent, everyNSeconds, eventGenerator, plusOrMinusNSeconds, upToNEvents ) )

    ###########################################################################
    #   PUBLIC FUNCTIONALITY
    ###########################################################################
    def stop( self ):
        self._stopEvent.set()

    def scheduleEvent( self, everyNSeconds, eventGenerator, plusOrMinusNSeconds = 0, upToNEvents = None ):
        self._threads.add( gevent.spawn_later( 0, self._generateEvent, everyNSeconds, eventGenerator, plusOrMinusNSeconds, upToNEvents ) )

    ###########################################################################
    #   MAIN
    ###########################################################################
    def _run( self ):
        try:
            self._log( "Starting virtual sensor: %s" % AgentId( ( self._oid, self._iid, self._sid, self._plat, self._arch ) ) )

            self._connect()

            self._stopEvent.wait()

            self._disconnect()
        except:
            self._log( "Exception:: %s" % traceback.format_exc() )
        self._log( "Sensor exited" )
