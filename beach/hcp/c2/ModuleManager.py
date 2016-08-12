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
import traceback
import hashlib
import time
import ipaddress
CassDb = Actor.importLib( '../utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( '../utils/hcp_databases', 'CassPool' )
rpcm = Actor.importLib( '../utils/rpcm', 'rpcm' )
rList = Actor.importLib( '../utils/rpcm', 'rList' )
rSequence = Actor.importLib( '../utils/rpcm', 'rSequence' )
AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )

class TaskingRule( object ):
    def __init__( self, parent, aid, mid, h ):
        self._parent = parent
        self._aid = AgentId( aid )
        self._mid = mid
        self._h = h

    def isMatch( self, aid ):
        if not AgentId( aid ).inSubnet( self._aid ):
            return False
        return ( self._mid, self._h )

class ModuleManager( Actor ):
    def init( self, parameters, resources ):
    	self._db = CassDb( parameters[ 'db' ], 'hcp_analytics', consistencyOne = True )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )

        self.loadModules = self.db.prepare( 'SELECT mid, mhash, mdat, msig FROM hcp_modules' )
        self.loadTaskings = self.db.prepare( 'SELECT aid, mid, mhash FROM hcp_module_tasking' )

        self.db.start()

        self.modules = {}
        self.taskings = []

    	self.reloadTaskings()

        self.handle( 'sync', self.sync )
        self.handle( 'reload', self.reloadTaskings )

    def deinit( self ):
        pass

    def sync( self, msg ):
    	changes = { 'unload' : [], 'load' : [] }
    	aid = msg.data[ 'aid' ]

    	loaded = {}

    	for mod in msg.data[ 'mods' ]:
    		loaded[ mod[ 'base.HASH' ].encode( 'hex' ) ] = mod[ 'hcp.MODULE_ID' ]

    	shouldBeLoaded = {}

    	for rule in self.taskings:
    		match = rule.isMatch( aid )
    		if match is not False:
    			shouldBeLoaded[ match[ 0 ] ] = match[ 1 ]

    	for iLoaded, hLoaded in loaded.iteritems():
    		if hLoaded not in shouldBeLoaded or iLoaded != shouldBeLoaded[ hLoaded ]:
    			changes[ 'unload' ].append( iLoaded )

    	for iToLoad, hToLoad in shouldBeLoaded.iteritems():
    		if hToLoad not in loaded or iToLoad != loaded[ hToLoad ]:
    			modInfo = self.modules.get( hToLoad, None )
    			if modInfo is not None:
    				changes[ 'load' ].append( modInfo )
    			else:
    				self.log( 'could not send module %s for load' % hToLoad )

        return ( True, { 'changes' : changes } )

    def reloadTaskings( self, msg = None ):
    	newModules = {}
    	for row in self.db.execute( self.loadModules.bind( tuple() ) ):
    		newModules[ row[ 1 ] ] = ( row[ 0 ], row[ 1 ], row[ 2 ], row[ 3 ] )

    	newTaskings = []
    	for row in self.db.execute( self.loadTaskings.bind( tuple() ) ):
    		newTaskings.append( TaskingRule( self, row[ 0 ], row[ 1 ], row[ 2 ] ) )

    	self.modules = newModules
    	self.taskings = newTaskings

    	self.log( 'reloade %d modules and %d taskings' % ( len( newModules ), len( newTaskings ) ) )

    	return ( True, )
