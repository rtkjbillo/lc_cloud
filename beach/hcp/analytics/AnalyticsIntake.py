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
EventObjectExtractor = Actor.importLib( '../utils/EventObjectExtractor', 'EventObjectExtractor' )

class AnalyticsIntake( Actor ):
    def init( self, parameters, resources ):
        self.modelingLevel = 10
        self.deploymentmanager = self.getActorHandle( resources[ 'deployment' ], timeout = 30, nRetries = 3 )
        self.refreshConfigs()
        self.handle( 'analyze', self.analyze )
        self.analytics_stateless = self.getActorHandle( resources[ 'stateless' ], timeout = 30, nRetries = 3 )
        self.analytics_stateful = self.getActorHandle( resources[ 'stateful' ], timeout = 30, nRetries = 3 )
        self.analytics_modeling = self.getActorHandle( resources[ 'modeling' ], timeout = 1200, nRetries = 3 )
        self.async_builder = self.getActorHandle( resources[ 'relation_builder' ], timeout = 1200, nRetries = 3 )
        self.analytics_investigation = self.getActorHandle( resources[ 'investigation' ], timeout = 1200, nRetries = 3 )

        self.processedCounter = 0

    def deinit( self ):
        pass

    def refreshConfigs( self ):
        resp = self.deploymentmanager.request( 'get_global_config', {} )
        if not resp.isSuccess:
            self.logCritical( "could not get global configs: %s" % resp )
        elif 'global/modeling_level' not in resp.data:
            self.log( "modeling level config not set, assuming full" )
        else:
            self.modelingLevel = resp.data[ 'global/modeling_level' ]

        self.delay( 60 * 5, self.refreshConfigs )


    def _extractObjects( self, message ):
        routing, event = message

        mtd = EventObjectExtractor.extractFromEvent( event, routing[ 'aid' ] )

        return ( routing, event, mtd )

    def analyze( self, msg ):

        for i in range( len( msg.data ) ):
            self.processedCounter += 1
            if 0 == ( self.processedCounter % 1000 ):
                self.log( 'ANA_IN %s' % self.processedCounter )

        for event in msg.data:
            # Enhance the data
            event = self._extractObjects( event )

            # Send the events to actual analysis
            if 0 != self.modelingLevel:
                self.analytics_modeling.shoot( 'analyze', event )
                self.async_builder.shoot( 'analyze', event )
            self.analytics_stateless.shoot( 'analyze', event )
            self.analytics_stateful.shoot( 'analyze', event )

            routing, rawEvent, mtd = event
            if 'investigation_id' in routing:
                self.analytics_investigation.shoot( 'analyze', event )
                self.log( 'routing event to investigation (%d)' % self.analytics_investigation.getNumAvailable() )

        return ( True, )


