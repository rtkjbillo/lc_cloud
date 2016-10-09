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
_xm_ = Actor.importLib( '../../utils/hcp_helpers', '_xm_' )

class ActiveDirectoryReference ( StatelessActor ):
    def init( self, parameters, resources ):
        super( ActiveDirectoryReference, self ).init( parameters, resources )

    def process( self, detects, msg ):
        routing, event, mtd = msg.data

        for filePath in _xm_( event, '?/base.COMMAND_LINE' ):
            if 'ntds.dit' in filePath.lower():
                detects.add( 90, 
                             'command line referencing the active directory database file',
                             event )
