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
_x_ = Actor.importLib( './hcp_helpers', '_x_' )
_xm_ = Actor.importLib( './hcp_helpers', '_xm_' )
exeFromPath = Actor.importLib( './hcp_helpers', 'exeFromPath' )
normalAtom = Actor.importLib( './hcp_helpers', 'normalAtom' )
ObjectTypes = Actor.importLib( './ObjectsDb', 'ObjectTypes' )

# The event tuples are: ( eventTypeDescription, funcForKey, funcForShortKey, funcForNarrative )

_eventTypes = {
	'notification.NEW_PROCESS' : ( 'new process starting',
								   lambda x: _x_( x, '?/base.FILE_PATH' ),
								   lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ),
								   lambda x: 'The process %s with pid %s is starting.' % ( _x_( x, '?/base.FILE_PATH' ),
								   														   _x_( x, '?/base.PROCESS_ID' ) ),
								   lambda x: ( exeFromPath( _x_( x, '?/base.FILE_PATH' ) ), ObjectTypes.PROCESS_NAME ) ),
	'notification.EXISTING_PROCESS' : ( 'pre-existing process',
								   lambda x: _x_( x, '?/base.FILE_PATH' ),
								   lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ),
								   lambda x: 'The process %s with pid %s is already running.' % ( _x_( x, '?/base.FILE_PATH' ),
								   														          _x_( x, '?/base.PROCESS_ID' ) ),
								   lambda x: ( exeFromPath( _x_( x, '?/base.FILE_PATH' ) ), ObjectTypes.PROCESS_NAME ) ),
	'notification.TERMINATE_PROCESS' : ( 'a process is terminating',
										 lambda x: _x_( x, '?/base.PROCESS_ID' ),
										 lambda x: _x_( x, '?/base.PROCESS_ID' ),
										 lambda x: 'The process with pid %s is terminating.' % ( _x_( x, '?/base.PROCESS_ID' ), ),
										 lambda x: ( None, None ) ),
	'notification.CODE_IDENTITY' : ( 'new unique code executed',
									 lambda x: _x_( x, '?/base.FILE_PATH' ),
									 lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ),
									 lambda x: 'The code on disk at %s was executed for the first time.' % ( _x_( x, '?/base.FILE_PATH' ), ),
									 lambda x: ( _x_( x, '?/base.HASH' ), ObjectTypes.FILE_HASH ) ),
	'notification.DNS_REQUEST' : ( 'new domain name request',
								   lambda x: _x_( x, '?/base.DOMAIN_NAME' ),
								   lambda x: _x_( x, '?/base.DOMAIN_NAME' ),
								   lambda x: 'A request for the domain name %s.' % ( _x_( x, '?/base.DOMAIN_NAME' ), ),
								   lambda x: ( _x_( x, '?/base.DOMAIN_NAME' ), ObjectTypes.DOMAIN_NAME ) ),
	'notification.MODULE_LOAD' : ( 'a module is being loaded',
						   		   lambda x: _x_( x, '?/base.FILE_PATH' ),
								   lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ),
								   lambda x: 'The code on disk at %s was loaded into %s.' % ( _x_( x, '?/base.FILE_PATH' ),
								 						  									  _x_( x, '?/base.PROCESS_ID' ) ),
								   lambda x: ( exeFromPath( _x_( x, '?/base.FILE_PATH' ) ), ObjectTypes.MODULE_NAME ) ),
	'notification.FILE_CREATE' : ( 'a file is created',
								   lambda x: _x_( x, '?/base.FILE_PATH' ),
								   lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ),
								   lambda x: 'The process %s created the file %s.' % ( _x_( x, '?/base.PROCESS_ID' ),
								   													   _x_( x, '?/base.FILE_PATH' ) ),
								   lambda x: ( None, None ) ),
	'notification.FILE_DELETE' : ( 'a file is deleted',
								   lambda x: _x_( x, '?/base.FILE_PATH' ),
								   lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ),
								   lambda x: 'The process %s deleted the file %s.' % ( _x_( x, '?/base.PROCESS_ID' ),
								   													   _x_( x, '?/base.FILE_PATH' ) ),
								   lambda x: ( None, None ) ),
	'notification.FILE_MODIFIED' : ( 'a file is modified',
								     lambda x: _x_( x, '?/base.FILE_PATH' ),
								     lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ),
								     lambda x: 'The process %s modified the file %s.' % ( _x_( x, '?/base.PROCESS_ID' ),
								     									 				  _x_( x, '?/base.FILE_PATH' ) ),
								     lambda x: ( None, None ) ),
	'notification.FILE_READ' : ( 'a file is read',
							     lambda x: _x_( x, '?/base.FILE_PATH' ),
							     lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ),
							     lambda x: 'The process %s read the file %s.' % ( _x_( x, '?/base.PROCESS_ID' ),
							     									 			  _x_( x, '?/base.FILE_PATH' ) ),
							     lambda x: ( None, None ) ),
}

class EventInterpreter( object ):
	def __init__( self, event = None ):
		if event is not None:
			self.setEvent( event )

	def setEvent( self, event ):
		self.event = event
		self.eventType = event.keys()[ 0 ]

	def description( self ):
		return _eventTypes.get( self.eventType, ( None, None, None, None ) )[ 0 ]

	def name( self ):
		return self.eventType.split( '.' )[ -1 ]

	def key( self ):
		f = _eventTypes.get( self.eventType, ( None, None, None, None ) )[ 1 ]
		if f is not None:
			return f( self.event )
		else:
			return None

	def shortKey( self ):
		f = _eventTypes.get( self.eventType, ( None, None, None, None ) )[ 2 ]
		if f is not None:
			return f( self.event )
		else:
			return None

	def narrative( self ):
		f = _eventTypes.get( self.eventType, ( None, None, None, None ) )[ 3 ]
		if f is not None:
			return f( self.event )
		else:
			return None

	def object( self ):
		f = _eventTypes.get( self.eventType, ( None, None, None, None ) )[ 4 ]
		if f is not None:
			return f( self.event )
		else:
			return ( None, None )

	def getAtom( self ):
		return normalAtom( _x_( self.event, '?/hbs.THIS_ATOM' ) )

	def getParentAtom( self ):
		return normalAtom( _x_( self.event, '?/hbs.PARENT_ATOM' ) )

	def __str__( self ):
		return '%s( %s )' % ( self.name(), self.key() )