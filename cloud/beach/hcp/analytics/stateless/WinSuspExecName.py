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
import re
ObjectTypes = Actor.importLib( '../../ObjectsDb', 'ObjectTypes' )
StatelessActor = Actor.importLib( '../../Detects', 'StatelessActor' )
_xm_ = Actor.importLib( '../../hcp_helpers', '_xm_' )

class WinSuspExecName ( StatelessActor ):
    def init( self, parameters ):
        super( WinSuspExecName, self ).init( parameters )
        self.susp = re.compile( r'.*((\.txt)|(\.doc)|(\.rtf)|(\.jpg)|(\.gif)|(\.pdf)|(\.wmi)|(\.avi)|( {5}.*))\.exe' )

    def process( self, msg ):
        routing, event, mtd = msg.data
        detects = []
        for filePath in _xm_( event, '?/base.FILE_PATH' ):
            if self.susp.match( filePath ):
                detects.append( ( event, ( ( 'remain_live', 60 ),
                                           ( 'history_dump', ),
                                           ( 'exfil_add', 'notification.FILE_CREATE', '--expire', 60 ) ) ) )
        return detects