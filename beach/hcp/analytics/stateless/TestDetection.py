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
StatelessActor = Actor.importLib( '../../Detects', 'StatelessActor' )
ObjectTypes = Actor.importLib( '../../ObjectsDb', 'ObjectTypes' )

class TestDetection ( StatelessActor ):
    def init( self, parameters ):
        super( TestDetection, self ).init( parameters )

    def process( self, msg ):
        routing, event, mtd = msg.data
        detects = []
        for o in mtd[ 'obj' ].get( ObjectTypes.FILE_PATH, [] ):
            if 'hcp_evil_detection_test' in o:
                detects.append( self.newDetect( objects = ( o, ObjectTypes.FILE_PATH ) ) )
                self.task( msg,
                           routing[ 'agentid' ],
                           ( 'file_hash',
                             event.get( 'notification.NEW_PROCESS', {} )
                                  .get( 'base.FILE_PATH' ) ) )
                self.log( "test detection triggered" )

        return detects