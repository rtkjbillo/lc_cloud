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
CassDb = Actor.importLib( 'utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( 'utils/hcp_databases', 'CassPool' )
rpcm = Actor.importLib( 'utils/rpcm', 'rpcm' )
rList = Actor.importLib( 'utils/rpcm', 'rList' )
rSequence = Actor.importLib( 'utils/rpcm', 'rSequence' )
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )
RingCache = Actor.importLib( 'utils/hcp_helpers', 'RingCache' )

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
        self.cacheSize = parameters.get( 'cache_size', 10 )
    	self._db = CassDb( parameters[ 'db' ], 'hcp_analytics', consistencyOne = True )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )

        self.loadTaskings = self.db.prepare( 'SELECT aid, mid, mhash FROM hcp_module_tasking' )
        self.loadModuleContent = self.db.prepare( 'SELECT mdat, msig FROM hcp_modules WHERE mid = ? AND mhash = ?' )

        self.db.start()

        self.taskings = []
        self.moduleCache = RingCache( self.cacheSize )

    	self.reloadTaskings()

        self.handle( 'sync', self.sync )
        self.handle( 'reload', self.reloadTaskings )

    def deinit( self ):
        pass

    def getModule( self, mid, mhash ):
        try:
            mdat, msig = self.moduleCache.get( ( mid, mhash ) )
            self.log( "Got module %s-%s in cache." % ( mid, mhash ) )
        except:
            mdat = None
            msig = None

        if mdat is None or msig is None:
            for row in self.db.execute( self.loadModuleContent.bind( ( mid, mhash ) ) ):
                mdat = row[ 0 ]
                msig = row[ 1 ]
                self.log( "Got module %s-%s from store." % ( mid, mhash ) )
                break
            self.moduleCache.add( ( mid, mhash ), ( mdat, msig ) )
        return ( mdat, msig )

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
    			shouldBeLoaded[ match[ 1 ] ] = match[ 0 ]

    	for hLoaded, iLoaded in loaded.iteritems():
    		if hLoaded not in shouldBeLoaded or iLoaded != shouldBeLoaded[ hLoaded ]:
    			changes[ 'unload' ].append( iLoaded )

        for hToLoad, iToLoad in shouldBeLoaded.iteritems():
            if hToLoad not in loaded or iToLoad != loaded[ hToLoad ]:
                dToLoad, sToLoad = self.getModule( iToLoad, hToLoad )
                modInfo = ( iToLoad, hToLoad, dToLoad, sToLoad )
                changes[ 'load' ].append( modInfo )

        return ( True, { 'changes' : changes } )

    def reloadTaskings( self, msg = None ):
    	newTaskings = []
    	for row in self.db.execute( self.loadTaskings.bind( tuple() ) ):
    		newTaskings.append( TaskingRule( self, row[ 0 ], row[ 1 ], row[ 2 ] ) )

    	self.taskings = newTaskings

    	self.log( 'reloaded %d taskings' % ( len( newTaskings ), ) )

    	return ( True, )
