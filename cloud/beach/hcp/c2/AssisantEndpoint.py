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
import time
from functools import wraps
AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )
_xm_ = Actor.importLib( '../utils/hcp_helpers', '_xm_' )
_x_ = Actor.importLib( '../utils/hcp_helpers', '_x_' )

def apiAiRequest( f ):
    @wraps( f )
    def wrapped( self, msg ):
        action = msg.data.get( 'result', {} ).get( 'action' )
        params = msg.data.get( 'result', {} ).get( 'parameters', {} )
        ctx = msg.data.get( 'result', {} ).get( 'contexts', [] )
        speech, displayText = f( self, action, params, ctx )
        return ( True,
                 { "speech" : speech, 
                   "displayText" : displayText, 
                   "source" : "lc-assistant" } )
    return wrapped

class AssistantEndpoint( Actor ):
    def init( self, parameters, resources ):
        self.model = self.getActorHandle( resources[ 'modeling' ], timeout = 15, nRetries = 0 )

        self.handle( 'count_sensors', self.count_sensors )

    def deinit( self ):
        pass

    @apiAiRequest
    def count_sensors( self, action, params, ctx ):
        resp = self.model.request( 'list_sensors', {} )
        if resp.isSuccess:
            sensors = resp.data.keys()
            platform = params.get( 'platform', None )
            platform = platform if ( platform is not None and platform != '' and platform != 'all' ) else None
            if platform is not None:
                if platform == 'osx':
                    sensors = [ x for x in sensors if AgentId( x ).isMacOSX() ]
                elif platform == 'windows':
                    sensors = [ x for x in sensors if AgentId( x ).isWindows() ]
                elif platform == 'linux':
                    sensors = [ x for x in sensors if AgentId( x ).isLinux() ]
            return ( "%s%s sensors are currently online." % ( len( sensors ), '' if ( platform is None ) else ( ' ' + platform ) ),
                     "%s%s are currently online." % ( len( sensors ), '' if ( platform is None ) else ( ' ' + platform ) ) )
        else:
            return( "Couldn't get sensor list.",
                    "Couldn't get sensor list." )
