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
ObjectTypes = Actor.importLib( '../../ObjectsDb', 'ObjectTypes' )
StatelessActor = Actor.importLib( '../../Detects', 'StatelessActor' )
_x_ = Actor.importLib( '../../hcp_helpers', '_x_' )

class ExecNotOnDisk ( StatelessActor ):
    def init( self, parameters ):
        super( ExecNotOnDisk, self ).init( parameters )

    def process( self, msg ):
        routing, event, mtd = msg.data
        detects = []

        if _x_( event, '?/base.HASH' ) is None:
            detects.append( ( event, None ) )

        return detects