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
_x_ = Actor.importLib( '../../hcp_helpers', '_x_' )
_xm_ = Actor.importLib( '../../hcp_helpers', '_xm_' )
SAMFilter = Actor.importLib( '.', 'SAMFilter' )

class SAMSelector( SAMFilter ):
    def __init__( self, *a, **k ):
        SAMFilter.__init__( self, *a, **k )
        for k, v in self.parameters.items():
            if type( v ) is str or type( v ) is unicode:
                self.parameters[ k ] = re.compile( v )

    def execute( self, newEvent ):
        out = None

        if 0 == len( self.parameters ):
            return newEvent

        isMatch = True

        for k, v in self.parameters.iteritems():
            isValFound = False
            for value in _xm_( newEvent, k ):
                if type( v ) is re._pattern_type:
                    if v.match( value ):
                        isValFound = True
                        break
                elif v is None or value == v:
                    isValFound = True
                    break

            if not isValFound:
                isMatch = False
                break

        if isMatch:
            out = newEvent

        return out