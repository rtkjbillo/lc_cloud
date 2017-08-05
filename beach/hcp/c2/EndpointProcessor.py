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

from beach.actor import Actor
import gevent
from gevent.lock import Semaphore
from gevent.server import StreamServer
import os
import sys
import struct
import msgpack
import ssl
import zlib
import uuid
import hashlib
import random
import traceback
import time
import tempfile
import netifaces
try:
    # Try to import any onboarded versions first.
    # Users may cythonize rpcm for performance.
    from rpcm import rpcm
    from rpcm import rList
    from rpcm import rSequence
except:
    rpcm = Actor.importLib( 'utils/rpcm', 'rpcm' )
    rList = Actor.importLib( 'utils/rpcm', 'rList' )
    rSequence = Actor.importLib( 'utils/rpcm', 'rSequence' )
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )
HcpModuleId = Actor.importLib( 'utils/hcp_helpers', 'HcpModuleId' )
Symbols = Actor.importLib( 'Symbols', 'Symbols' )()
HcpOperations = Actor.importLib( 'utils/hcp_helpers', 'HcpOperations' )
LimitedQPSBuffer = Actor.importLib( 'utils/hcp_helpers', 'LimitedQPSBuffer' )

class DisconnectException( Exception ):
    pass

class _ClientContext( object ):
    def __init__( self, parent, socket ):
        self.parent = parent

        # A simple connection header sent by the proxy before the connection
        # content, it encapsulates the original connection source information.
        self.address = msgpack.unpackb( socket.recv( struct.unpack( '!I', socket.recv( 4 ) )[ 0 ] ) )
        self.parent.log( 'Remote address: %s' % str( self.address ) )

        try:
            socket = parent.sslContext.wrap_socket( socket, 
                                                    server_side = True, 
                                                    do_handshake_on_connect = True,
                                                    suppress_ragged_eofs = True )
        except:
            raise DisconnectException
        self.s = socket
        self.aid = None
        self.lock = Semaphore( 1 )
        self.r = rpcm( isHumanReadable = True, isDebug = self.parent.log )
        self.r.loadSymbols( Symbols.lookups )
        self.connId = uuid.uuid4()
        self.hostName = None
        self.int_ip = None
        self.ext_ip = None
        self.tags = []

    def setAid( self, aid ):
        self.aid = aid

    def getAid( self ):
        return self.aid

    def close( self ):
        with self.lock:
            self.s.close()

    def recvData( self, size, timeout = None ):
        data = None
        timeout = gevent.Timeout( timeout )
        timeout.start()
        try:
            data = ''
            while size > len( data ):
                tmp = self.s.recv( size - len( data ) )
                if not tmp:
                    raise DisconnectException( 'disconnect while receiving' )
                    break
                data += tmp
        except:
            raise
        finally:
            timeout.cancel()
        return data

    def sendData( self, data, timeout = None ):
        timeout = gevent.Timeout( timeout )
        timeout.start()
        try:
            with self.lock:
                self.s.sendall( data )
        except:
            raise DisconnectException( 'disconnect while sending' )
        finally:
            timeout.cancel()

    def recvFrame( self, timeout = None ):
        frameSize = struct.unpack( '>I', self.recvData( 4, timeout = timeout ) )[ 0 ]
        if (1024 * 1024 * 50) < frameSize:
            raise Exception( "frame size too large: %s" % frameSize )
        frame = self.recvData( frameSize, timeout = timeout )
        frame = zlib.decompress( frame )
        moduleId = struct.unpack( 'B', frame[ : 1 ] )[ 0 ]
        frame = frame[ 1 : ]
        self.r.setBuffer( frame )
        messages = self.r.deserialise( isList = True )
        return ( moduleId, messages, frameSize + 4 )

    def sendFrame( self, moduleId, messages, timeout = None ):
        msgList = rList()
        for msg in messages:
            msgList.addSequence( Symbols.base.MESSAGE, msg )
        hcpData = struct.pack( 'B', moduleId ) + self.r.serialise( msgList )
        data = struct.pack( '>I', len( hcpData ) )
        data += zlib.compress( hcpData )
        self.sendData( struct.pack( '>I', len( data ) ) + data, timeout = timeout )

class EndpointProcessor( Actor ):
    def init( self, parameters, resources ):
        self.handlerPortStart = parameters.get( 'handler_port_start', 10000 )
        self.handlerPortEnd = parameters.get( 'handler_port_end', 20000 )
        self.bindAddress = parameters.get( 'handler_address', '0.0.0.0' )
        self.bindInterface = parameters.get( 'handler_interface', None )
        self.sensorMaxQps = parameters.get( 'sensor_max_qps', 30 )
        
        if self.bindInterface is not None:
            ip4 = self.getIpv4ForIface( self.bindInterface )
            if ip4 is not None:
                self.bindAddress = ip4
        elif '0.0.0.0' == self.bindAddress:
            self.bindAddress = self.getIpv4ForIface( self.getPublicInterfaces()[ 0 ] )

        self.r = rpcm( isHumanReadable = True )
        self.r.loadSymbols( Symbols.lookups )

        self.analyticsIntake = self.getActorHandle( resources[ 'analytics' ], nRetries = 3 )
        self.enrollmentManager = self.getActorHandle( resources[ 'enrollments' ], nRetries = 3 )
        self.stateChanges = self.getActorHandleGroup( resources[ 'states' ], nRetries = 3 )
        self.sensorDir = self.getActorHandle( resources[ 'sensordir' ], nRetries = 3 )
        self.moduleManager = self.getActorHandle( resources[ 'module_tasking' ], nRetries = 3 )
        self.hbsProfileManager = self.getActorHandle( resources[ 'hbs_profiles' ], nRetries = 3 )
        self.deploymentManager = self.getActorHandle( resources[ 'deployment' ], nRetries = 3 )
        self.tagging = self.getActorHandle( resources[ 'tagging' ], nRetries = 3 )

        self.privateKey = parameters.get( '_priv_key', None )
        self.privateCert = parameters.get( '_priv_cert', None )

        self.sslContext = ssl.SSLContext( ssl.PROTOCOL_TLSv1_2 )

        if self.privateKey is None or self.privateCert is None:
            resp = self.deploymentManager.request( 'get_c2_cert', {}, timeout = 300 )
            if resp.isSuccess:
                self.privateKey = resp.data[ 'key' ]
                self.privateCert = resp.data[ 'cert' ]

                tmpHandle, tmpPathKey = tempfile.mkstemp()
                with open( tmpPathKey, 'wb' ) as f:
                    f.write( self.privateKey )
                os.close( tmpHandle )

                tmpHandle, tmpPathCert = tempfile.mkstemp()
                with open( tmpPathCert, 'wb' ) as f:
                    f.write( self.privateCert )
                os.close( tmpHandle )

                self.log( 'got keys from deployment manager' )
                self.sslContext.load_cert_chain( certfile = tmpPathCert, keyfile = tmpPathKey )
                
                os.unlink( tmpPathKey )
                os.unlink( tmpPathCert )
            else:
                raise Exception( 'no cert specified in parameters or through deployment manager' )
        else:
            self.log( 'got keys from disk' )
            self.sslContext.load_cert_chain( certfile = self.privateCert, keyfile = self.privateKey )

        self.sslContext.set_ciphers( 'ECDHE-RSA-AES128-GCM-SHA256' )

        self.handle( 'task', self.taskClient )
        self.handle( 'report', self.report )
        self.handle( 'add_tag', self.addTag )
        self.handle( 'del_tag', self.delTag )

        self.server = None
        self.serverPort = random.randint( self.handlerPortStart, self.handlerPortEnd )
        self.currentClients = {}
        self.moduleHandlers = { HcpModuleId.HCP : self.handlerHcp,
                                HcpModuleId.HBS : self.handlerHbs }

        self.processedCounter = 0

        self.startServer()

    def deinit( self ):
        if self.server is not None:
            self.server.close()

    def startServer( self ):
        if self.server is not None:
            self.server.close()
        while True:
            try:
                self.server = StreamServer( ( self.bindAddress, self.serverPort ), self.handleNewClient )
                self.server.start()
                self.log( 'Starting server on port %s' % self.serverPort )
                break
            except:
                self.serverPort = random.randint( self.handlerPortStart, self.handlerPortEnd )

    def getIpv4ForIface( self, iface ):
        ip = None
        try:
            ip = netifaces.ifaddresses( iface )[ netifaces.AF_INET ][ 0 ][ 'addr' ]
        except:
            ip = None
        return ip

    def getPublicInterfaces( self ):
        interfaces = []

        for iface in netifaces.interfaces():
            ipv4s = netifaces.ifaddresses( iface ).get( netifaces.AF_INET, [] )
            for entry in ipv4s:
                addr = entry.get( 'addr' )
                if not addr:
                    continue
                if not ( iface.startswith( 'lo' ) or addr.startswith( '127.' ) ):
                    interfaces.append( iface )
                    break

        return interfaces

    #==========================================================================
    # Client Handling
    #==========================================================================
    def handleNewClient( self, socket, address ):
        aid = None
        tmpBytesReceived = 0
        bufferedOutput = None

        self.log( 'New connection from %s:%s' % address )

        try:
            c = _ClientContext( self, socket )
            
            moduleId, headers, _ = c.recvFrame( timeout = 30.0 )
            if HcpModuleId.HCP != moduleId:
                raise DisconnectException( 'Headers not from expected module' )
            if headers is None:
                raise DisconnectException( 'Error deserializing headers' )
            headers = headers[ 0 ]
            self.log( 'Headers decoded, validating connection' )

            hostName = headers.get( 'base.HOST_NAME', None )
            internalIp = headers.get( 'base.IP_ADDRESS', None )
            hcpHash = headers.get( 'base.HASH', None )
            # Use the address in the client context since it was received from the
            # proxy headers and therefore is the correct original source.
            externalIp = c.address[ 0 ]
            c.hostName = hostName
            c.int_ip = internalIp
            c.ext_ip = externalIp
            aid = AgentId( headers[ 'base.HCP_IDENT' ] )
            if aid.org_id is None or aid.ins_id is None or aid.platform is None or aid.architecture is None:
                aidInfo = str( aid )
                if 0 == len( aidInfo ):
                    aidInfo = str( headers )
                raise DisconnectException( 'Invalid sensor id: %s' % aidInfo )

            if aid.sensor_id is None:
                self.log( 'Sensor requires enrollment' )
                resp = self.enrollmentManager.request( 'enroll', { 'aid' : aid.asString(),
                                                                   'public_ip' : externalIp,
                                                                   'internal_ip' : internalIp,
                                                                   'host_name' : hostName },
                                                       timeout = 30 )
                if not resp.isSuccess or 'aid' not in resp.data or resp.data[ 'aid' ] is None:
                    raise DisconnectException( 'Sensor could not be enrolled, come back later' )
                aid = AgentId( resp.data[ 'aid' ] )
                enrollmentToken = resp.data[ 'token' ]
                self.log( 'Sending sensor enrollment to %s' % aid.asString() )
                c.sendFrame( HcpModuleId.HCP,
                             ( rSequence().addInt8( Symbols.base.OPERATION, 
                                                    HcpOperations.SET_HCP_ID )
                                          .addSequence( Symbols.base.HCP_IDENT, 
                                                        aid.toJson() )
                                          .addBuffer( Symbols.hcp.ENROLLMENT_TOKEN, 
                                                      enrollmentToken ), ) )
            else:
                enrollmentToken = headers.get( 'hcp.ENROLLMENT_TOKEN', None )
                resp = self.enrollmentManager.request( 'authorize', { 'aid' : aid.asString(), 
                                                                      'token' : enrollmentToken,
                                                                      'hash' : hcpHash }, timeout = 10 )
                if not resp.isSuccess or not resp.data.get( 'is_authorized', False ):
                    raise DisconnectException( 'Could not authorize %s' % aid )

            self.log( 'Valid client connection' )

            # Eventually sync the clocks at recurring intervals
            c.sendFrame( HcpModuleId.HCP, ( self.timeSyncMessage(), ) )

            c.setAid( aid )
            self.currentClients[ aid.sensor_id ] = c
            newStateMsg = { 'aid' : aid.asString(), 
                            'endpoint' : self.name,
                            'ext_ip' : externalIp,
                            'int_ip' : internalIp,
                            'hostname' : hostName,
                            'connection_id' : c.connId }
            self.stateChanges.shoot( 'live', newStateMsg, timeout = 30 )
            self.sensorDir.broadcast( 'live', newStateMsg )
            del( newStateMsg )

            resp = self.tagging.request( 'get_tags', { 'sid' : aid.sensor_id }, timeout = 2 )
            if resp.isSuccess:
                c.tags = resp.data.get( 'tags', {} ).values()[ 0 ].keys()
                self.log( 'Retrieved tags %s for %s' % ( c.tags, aid.asString() ) )

            self.log( 'Client %s registered, beginning to receive data' % aid.asString() )
            lastTransferReport = time.time()
            frameIndex = 0
            bufferedOutput = LimitedQPSBuffer( self.sensorMaxQps, cbLog = lambda x: self.log( "%s %s" % ( aid.asString(), x ) ) )
            while True:
                moduleId, messages, nRawBytes = c.recvFrame( timeout = 60 * 60 )
                tmpBytesReceived += nRawBytes
                if 10 == frameIndex:
                    now = time.time()
                    if now > lastTransferReport + ( 60 * 10 ):
                        self.sensorDir.broadcast( 'transfered', { 'aid' : aid.asString(), 
                                                                  'bytes_transfered' : tmpBytesReceived } )
                        self.stateChanges.shoot( 'transfered', { 'aid' : aid.asString(), 
                                                                 'bytes_transfered' : tmpBytesReceived } )
                        tmpBytesReceived = 0
                        lastTransferReport = now
                    frameIndex = 0
                else:
                    frameIndex += 1
                handler = self.moduleHandlers.get( moduleId, None )
                
                if handler is None:
                    self.log( 'Received data for unknown module' )
                else:
                    bufferedOutput.add( handler, c, messages )

        except Exception as e:
            if type( e ) is not DisconnectException:
                self.log( 'Exception while processing: %s' % str( e ) )
                self.log( traceback.format_exc() )
                raise
            else:
                self.log( 'Disconnecting: %s' % str( e ) )
        finally:
            if aid is not None:
                if aid.sensor_id in self.currentClients:
                    del( self.currentClients[ aid.sensor_id ] )
                    self.sensorDir.broadcast( 'transfered', { 'aid' : aid.asString(), 
                                                              'bytes_transfered' : tmpBytesReceived } )
                    self.stateChanges.shoot( 'transfered', { 'aid' : aid.asString(), 
                                                             'bytes_transfered' : tmpBytesReceived } )
                    newStateMsg = { 'aid' : aid.asString(), 
                                    'endpoint' : self.name,
                                    'connection_id' : c.connId }
                    self.stateChanges.shoot( 'dead', newStateMsg, timeout = 30 )
                    self.sensorDir.broadcast( 'dead', newStateMsg )
                    del( newStateMsg )
                self.log( 'Connection terminated: %s' % aid.asString() )
            else:
                self.log( 'Connection terminated: %s:%s' % address )

            if bufferedOutput is not None:
                qSize = bufferedOutput.size()
                if 0 != qSize:
                    self.log( 'Waiting for queue of size %s to flush for %s' % ( qSize, aid.asString() ) )
                bufferedOutput.close()
                if 0 != qSize:
                    self.log( 'Queue for %s finished flushing' % aid.asString() )

    def handlerHcp( self, c, messages ):
        for message in messages:
            if 'hcp.MODULES' in message:
                moduleUpdateResp = self.moduleManager.request( 'sync', 
                                                               { 'mods' : message[ 'hcp.MODULES' ],
                                                                 'aid' : c.getAid(),
                                                                 'tags' : c.tags },
                                                               timeout = 30 )
                if moduleUpdateResp.isSuccess:
                    changes = moduleUpdateResp.data[ 'changes' ]
                    tasks = []
                    for mod in changes[ 'unload' ]:
                        tasks.append( rSequence().addInt8( Symbols.base.OPERATION,
                                                           HcpOperations.UNLOAD_MODULE )
                                                 .addInt8( Symbols.hcp.MODULE_ID,
                                                           mod ) )
                    for mod in changes[ 'load' ]:
                        tasks.append( rSequence().addInt8( Symbols.base.OPERATION,
                                                           HcpOperations.LOAD_MODULE )
                                                 .addInt8( Symbols.hcp.MODULE_ID,
                                                           mod[ 0 ] )
                                                 .addBuffer( Symbols.base.BINARY,
                                                             mod[ 2 ] )
                                                 .addBuffer( Symbols.base.SIGNATURE,
                                                             mod[ 3 ] ) )

                    c.sendFrame( HcpModuleId.HCP, tasks )
                    self.log( 'load %d modules, unload %d modules' % ( len( changes[ 'load' ] ),
                                                                       len( changes[ 'unload' ] ) ) )
                else:
                    self.log( "could not provide module sync: %s" % moduleUpdateResp.error )

    def handlerHbs( self, c, messages ):
        for i in range( len( messages ) ):
            self.processedCounter += 1

            if 0 == ( self.processedCounter % 1000 ):
                self.log( 'EP_IN %s' % self.processedCounter )

        for message in messages:
            # We treat sync messages slightly differently since they need to be actioned
            # more directly.
            if 'notification.SYNC' in message:
                self.log( "sync received from %s" % c.getAid() )
                profileHash = message[ 'notification.SYNC' ].get( 'base.HASH', None )
                profileUpdateResp = self.hbsProfileManager.request( 'sync', 
                                                                    { 'hprofile' : profileHash,
                                                                      'aid' : c.getAid(),
                                                                      'tags' : c.tags },
                                                                    timeout = 30 )
                if profileUpdateResp.isSuccess and 'changes' in profileUpdateResp.data:
                    profile = profileUpdateResp.data[ 'changes' ].get( 'profile', None )
                    if profile is not None:
                        r = rpcm( isHumanReadable = False, isDebug = self.log, isDetailedDeserialize = True )
                        r.setBuffer( profile [ 0 ] )
                        realProfile = r.deserialise( isList = True )
                        if realProfile is not None:
                            syncProfile = rSequence().addSequence( Symbols.notification.SYNC,
                                                                   rSequence().addBuffer( Symbols.base.HASH,
                                                                                          profile[ 1 ].decode( 'hex' ) )
                                                                              .addList( Symbols.hbs.CONFIGURATIONS,
                                                                                        realProfile ) )
                            c.sendFrame( HcpModuleId.HBS, ( syncProfile, ) )
                            self.log( "sync profile sent to %s" % c.getAid() )
                            
            # Transmit the message to the analytics cloud.
            routing = { 'aid' : c.getAid(),
                        'hostname' : c.hostName,
                        'int_ip' : c.int_ip,
                        'ext_ip' : c.ext_ip,
                        'moduleid' : HcpModuleId.HBS,
                        'event_type' : message.keys()[ 0 ],
                        'event_id' : uuid.uuid4(),
                        'tags' : c.tags }
            invId = message.values()[ 0 ].get( 'hbs.INVESTIGATION_ID', None )
            if invId is not None:
                routing[ 'investigation_id' ] = invId
            self.analyticsIntake.shoot( 'analyze', ( ( routing, message ), ), timeout = 600 )

    def timeSyncMessage( self ):
        return ( rSequence().addInt8( Symbols.base.OPERATION,
                                      HcpOperations.SET_GLOBAL_TIME )
                            .addTimestamp( Symbols.base.TIMESTAMP,
                                           int( time.time() ) ) )

    def taskClient( self, msg ):
        aid = AgentId( msg.data[ 'aid' ] )
        messages = msg.data[ 'messages' ]
        moduleId = msg.data[ 'module_id' ]
        c = self.currentClients.get( aid.sensor_id, None )
        if c is not None:
            outMessages = []
            r = rpcm( isHumanReadable = False, isDebug = self.log, isDetailedDeserialize = True )
            for message in messages:
                r.setBuffer( message )
                outMessages.append( r.deserialise( isList = False ) )
            c.sendFrame( moduleId, outMessages, timeout = 60 * 10 )
            return ( True, )
        else:
            return ( False, )

    def report( self, msg ):
        return ( True, { 'address' : self.bindAddress, 'port' : self.serverPort } )

    def addTag( self, msg ):
        sid = AgentId( msg.data[ 'sid' ] ).sensor_id
        tag = msg.data[ 'tag' ]
        c = self.currentClients.get( sid, None )
        if c is not None:
            if tag not in c.tags:
                c.tags.append( tag )
            return ( True, )
        return ( False, 'sensor not online' )

    def delTag( self, msg ):
        sid = AgentId( msg.data[ 'sid' ] ).sensor_id
        tag = msg.data[ 'tag' ]
        c = self.currentClients.get( sid, None )
        if c is not None:
            if tag in c.tags:
                try:
                    c.tags.remove( tag )
                except:
                    pass
            return ( True, )
        return ( False, 'sensor not online' )