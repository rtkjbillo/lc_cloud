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
AgentId = Actor.importLib( '../hcp_helpers', 'AgentId' )

import time

class AnalyticsInvestigation( Actor ):
    def init( self, parameters, resources ):
        self.ttl = parameters.get( 'ttl', 60 * 60 * 24 )
        self.handleCache = {}
        self.handleTtl = {}
        self.invPath = resources[ 'investigations' ]

        self.handle( 'analyze', self.analyze )
        self.schedule( 60, self.invCulling )

    def deinit( self ):
        pass

    def invCulling( self ):
        curTime = int( time.time() )
        inv_ids = [ inv_id for inv_id, ts in self.handleTtl.iteritems() if ts < ( curTime - self.ttl ) ]
        for inv_id in inv_ids:
            self.handleCache[ inv_id ].close()
            del( self.handleCache[ inv_id ] )
            del( self.handleTtl[ inv_id ] )

    def analyze( self, msg ):
        routing, event, mtd = msg.data

        inv_id = routing[ 'investigation_id' ]

        if inv_id not in self.handleCache:
            handle = self.getActorHandle( self.invPath % inv_id )
            self.handleCache[ inv_id ] = handle
            self.handleTtl[ inv_id ] = int( time.time() )
        else:
            handle = self.handleCache[ inv_id ]
            self.handleTtl[ inv_id ] = int( time.time() )

        self.log( 'investigation data going to: %d' % handle.getNumAvailable() )
        handle.broadcast( 'inv', msg.data )


        return ( True, )