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
rpcm = Actor.importLib( 'utils/rpcm', 'rpcm' )
rList = Actor.importLib( 'utils/rpcm', 'rList' )
rSequence = Actor.importLib( 'utils/rpcm', 'rSequence' )
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )
RingCache = Actor.importLib( 'utils/hcp_helpers', 'RingCache' )
HcpModuleId = Actor.importLib( 'utils/hcp_helpers', 'HcpModuleId' )
Symbols = Actor.importLib( 'Symbols', 'Symbols' )()

class TaskingProxy( Actor ):
    def init( self, parameters, resources ):
        self.cachedEndpoints = RingCache( maxEntries = 1000 )
        self.sensorDir = self.getActorHandle( resources[ 'sensor_dir' ] )
        self.handle( 'task', self.task )

    def deinit( self ):
        pass

    def getEndpointFor( self, aid ):
        endpoint = None
        if aid in self.cachedEndpoints:
            endpoint = self.cachedEndpoints.get( aid )
        else:
            resp = self.sensorDir.request( 'get_endpoint', { 'aid' : aid } )
            if resp.isSuccess:
                endpoint = resp.data[ 'endpoint' ]
                if endpoint is not None:
                    endpoint = self.getActorHandle( '_ACTORS/%s' % endpoint )
                    self.cachedEndpoints.add( aid, endpoint )
        return endpoint

    def task( self, msg ):
        aid = msg.data[ 'aid' ]
        messages = msg.data[ 'messages' ]
        moduleId = msg.data[ 'module_id' ]
        req = { 'aid' : aid, 'messages' : messages, 'module_id' : moduleId }
        for retry in range( 2 ):
            endpoint = self.getEndpointFor( aid )
            if endpoint is None:
                self.log( 'host %s not at any endpoint' % aid )
                break
            resp = endpoint.request( 'task', req )
            if resp.isSuccess:
                return ( True, )
            else:
                try:
                    endpoint.close()
                finally:
                    self.cachedEndpoints.remove( aid )
        return ( False, )
