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

class AnalyticsStateless( Actor ):
    def init( self, parameters ):
        self.handleCache = {}
        self.modules = {}

        self.handle( 'analyze', self.analyze )

    def deinit( self ):
        pass

    def analyze( self, msg ):
        routing, event, mtd = msg.data

        etype = routing[ 'event_type' ]

        if etype not in self.modules:
            self.log( "New stateless event: %s" % ('analytics/stateless/%s/' % etype,))
            self.modules[ etype ] = self.getActorHandleGroup( 'analytics/stateless/%s/' % etype, timeout = 30, nRetries = 3 )

        self.log( "Trying to send to %s: %d" % ( etype, self.modules[ etype ].getNumAvailable() ) )
        self.modules[ etype ].shoot( 'process', msg.data )

        return ( True, )