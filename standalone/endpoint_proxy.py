from gevent import monkey
monkey.patch_all()

import os
import sys

from beach.beach_api import Beach

import argparse
import socket
import gevent
import random
from sets import Set
from gevent.server import StreamServer
from gevent.socket import create_connection

class LcEndpointProxy ( StreamServer ):
	def __init__( self, listener, endpoints, **kwargs ):
		StreamServer.__init__( self, listener, **kwargs )

	def handle( self, source, address ):
		global currentEndpoints
		dest = create_connection( random.sample( currentEndpoints, 1 ) )

		forwarders = ( gevent.spawn( forward, source, dest, self ),
                       gevent.spawn( forward, dest, source, self ) )

        gevent.joinall( forwarders )

def forward( source, dest, server ):
	try:
		while True:
			data = source.recv( 4096 )
			if not data:
				break
			dest.sendall( data )
	finally:
		source.close()
     	dest.close()

def updateEndpoints( endpointActors, nextUpdate ):
	global currentEndpoints
	responses = endpointActors.requestFromAll( 'report' )
	
	newEndpoints = Set()
	while responses.waitForResults( timeout = 10 ):
		for response in responses.getNewResults():
			if response.isSuccess and 'address' in response.data and 'port' in response.data:
				newEndpoints.add( '%s:%s' % ( response.data[ 'address' ], response.data[ 'port' ] ) )
		if responses.isAllReceived: break

	currentEndpoints = newEndpoints

	print( "Updated list of endpoints, found %s" % len( currentEndpoints ) )
	gevent.spawn_later( nextUpdate, updateEndpoints, endpointActors, nextUpdate )

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
	                     dest = 'source' )
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

	updateEndpoints( currentEndpoints, endpointActors, arguments.update )

	proxy = LcEndpointProxy( arguments.source, currentEndpoints )
	proxy.start()
	gevent.wait()