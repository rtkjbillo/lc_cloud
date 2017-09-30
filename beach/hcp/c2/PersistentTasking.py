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
rpcm = Actor.importLib( 'utils/rpcm', 'rpcm' )
rList = Actor.importLib( 'utils/rpcm', 'rList' )
rSequence = Actor.importLib( 'utils/rpcm', 'rSequence' )
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )

class PersistentTasking( Actor ):
    def init( self, parameters, resources ):
        self.db = CassDb( parameters[ 'db' ], 'hcp_analytics' )

        #self.db.start()

        self.handle( 'live', self.setLive )
        self.handle( 'dead', self.setDead )

    def deinit( self ):
        self.db.shutdown()

    def setLive( self, msg ):
        aid = AgentId( msg.data[ 'aid' ] )
        
        # TODO implement the persistent queue.
        
        return ( True, )

    def setDead( self, msg ):
        aid = AgentId( msg.data[ 'aid' ] )
        
        # TODO implement the persistent queue.

        return ( True, )
