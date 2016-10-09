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
ObjectTypes = Actor.importLib( '../../utils/ObjectsDb', 'ObjectTypes' )
StatelessActor = Actor.importLib( '../../Detects', 'StatelessActor' )
_xm_ = Actor.importLib( '../../utils/hcp_helpers', '_xm_' )

class WinFirewallCliMods ( StatelessActor ):
    def init( self, parameters, resources ):
        super( WinFirewallCliMods, self ).init( parameters, resources )

        self.re_rule_modif = [ re.compile( r'.*firewall.*add.*rule.*', re.IGNORECASE ),
                      re.compile( r'.*firewall.*set.disable.*', re.IGNORECASE ),
                      re.compile( r'.*set.*state.*off.*', re.IGNORECASE ) ]
        self.re_known_good_rule = re.compile( r'.*rule name="system time".*', re.IGNORECASE )

    def process( self, detects, msg ):
        routing, event, mtd = msg.data
        
        for cmdline in _xm_( event, '?/base.COMMAND_LINE' ):
            for modif in self.re_rule_modif:
                if modif.search( cmdline ) and not self.re_known_good_rule.search( cmdline ):
                    detects.add( 30,
                                 'exception added or state changed of windows firewall',
                                 event )
