from gevent import monkey
monkey.patch_all()

import os
import sys

from beach.beach_api import Beach

import argparse
import socket
import gevent
import random
import msgpack
import struct
from sets import Set
from gevent.server import StreamServer
from gevent.socket import create_connection

class LcEndpointProxy ( StreamServer ):
    def __init__( self, listener, endpoints, **kwargs ):
        StreamServer.__init__( self, listener, **kwargs )

    def handle( self, source, address ):
        global currentEndpoints
        try:
            if 0 == len( currentEndpoints ): return

            print( "Connection from %s" % str( address ) )

            try:
            	source.setsockopt( socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1 )
            	source.setsockopt( socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 5 )
            	source.setsockopt( socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10 )
            	source.setsockopt( socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 2 )
            except:
            	print( "Failed to set keepalive on source connection" )

            try:
                dest = create_connection( random.sample( currentEndpoints, 1 )[ 0 ] )
            except:
            	print( "Failed to connect to EndpointProcessor" )
            else:
                try:
                    try:
                        dest.setsockopt( socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1 )
                        dest.setsockopt( socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 5 )
                        dest.setsockopt( socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10 )
                        dest.setsockopt( socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 2 )
                    except:
                        print( "Failed to set keepalive on dest connection" )

                    # Send a small connection header that contains the original
                    # source of the connection.
                    connectionHeaders = msgpack.packb( address )
                    dest.sendall( struct.pack( '!I', len( connectionHeaders ) ) )
                    dest.sendall( connectionHeaders )
                        
                    gevent.joinall( ( gevent.spawn( forward, source, dest, address, self ),
                                      gevent.spawn( forward, dest, source, address, self ) ) )
                finally:
                    dest.close()
        finally:
            source.close()

def forward( source, dest, address, server ):
    buff = bytearray( 4096 )
    mv_buffer = memoryview( buff )
    try:
        while True:
            nReceived = source.recv_into( buff )
            if 0 == nReceived:
                break
            dest.sendall( mv_buffer[ : nReceived ] )
    except:
    	pass
    finally:
        print( "Closed from %s" % str( address ) )
        try:
            source.close()
        except:
            pass
        try:
            dest.close()
        except:
            pass
        server = None

def updateEndpoints( endpointActors, nextUpdate ):
    global currentEndpoints
    endpointActors.forceRefresh()
    responses = endpointActors.requestFromAll( 'report' )
    
    newEndpoints = Set()
    while responses.waitForResults( timeout = 10 ):
        for response in responses.getNewResults():
            if response.isSuccess and 'address' in response.data and 'port' in response.data:
                newEndpoints.add( ( response.data[ 'address' ], response.data[ 'port' ] ) )
        if responses.isFinished(): break

    currentEndpoints = newEndpoints

    tmpUpdate = nextUpdate
    if 0 == len( currentEndpoints ):
        tmpUpdate = 5

    print( "Updated list of endpoints, found %s" % len( currentEndpoints ) )
    gevent.spawn_later( tmpUpdate, updateEndpoints, endpointActors, nextUpdate )

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument( '-c', '--config',
                         type = str,
                         required = True,
                         help = 'Path to beach config file.',
                         dest = 'config' )
    parser.add_argument( '-l', '--listen',
                         type = str,
                         required = True,
                         help = 'ip:port to listen for incoming connections on.',
                         dest = 'source' )
    parser.add_argument( '-i', '--ident',
                         type = str,
                         required = False,
                         default = 'endpointproxy/8e7a890b-8016-4396-b012-aec73d055dd6',
                         help = 'Beach identity to use to request list of endpoints.',
                         dest = 'ident' )
    parser.add_argument( '-u', '--update',
                         type = int,
                         required = False,
                         default = 60,
                         help = 'refresh list of available endpoints every X seconds.',
                         dest = 'update' )
    arguments = parser.parse_args()

    currentEndpoints = Set()
    beach = Beach( arguments.config, realm = 'hcp' )
    endpointActors = beach.getActorHandle( 'c2/endpoint', nRetries = 3, timeout = 30, ident = arguments.ident )

    updateEndpoints( endpointActors, arguments.update )

    proxy = LcEndpointProxy( arguments.source, currentEndpoints )
    proxy.start()
    gevent.wait()