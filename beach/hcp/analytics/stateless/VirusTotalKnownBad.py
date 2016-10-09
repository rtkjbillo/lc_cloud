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
ObjectTypes = Actor.importLib( '../../utils/ObjectsDb', 'ObjectTypes' )
StatelessActor = Actor.importLib( '../../Detects', 'StatelessActor' )
RingCache = Actor.importLib( '../../utils/hcp_helpers', 'RingCache' )

class VirusTotalKnownBad ( StatelessActor ):
    def init( self, parameters, resources ):
        super( VirusTotalKnownBad, self ).init( parameters, resources )

        self.vtReport = self.getActorHandle( 'analytics/virustotal' )

        # Minimum number of AVs saying it's a hit before we flag it
        self.threshold = parameters.get( 'min_av', 5 )

    def process( self, detects, msg ):
        routing, event, mtd = msg.data
        
        report = None
        for h in mtd[ 'obj' ].get( ObjectTypes.FILE_HASH, [] ):
            vtReport = self.vtReport.request( 'get_report', { 'hash' : h }, timeout = ( 60 * 30 ) )
            if vtReport.isSuccess:
                report = {}
                info = vtReport.data[ 'report' ]
                for av, r in info.iteritems():
                    if r is not None:
                        report[ av[ 0 ] ] = r
                if self.threshold > len( report ):
                    report = None

        if report is not None:
            detects.add( 70,
                         'bad hash from virus total',
                         { 'report' : report, 'hash' : h } )
