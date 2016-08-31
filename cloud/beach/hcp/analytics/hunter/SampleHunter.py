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
Hunter = Actor.importLib( '../../Hunters', 'Hunter' )
_xm_ = Actor.importLib( '../../utils/hcp_helpers', '_xm_' )
_x_ = Actor.importLib( '../../utils/hcp_helpers', '_x_' )
InvestigationNature = Actor.importLib( '../../utils/hcp_helpers', 'InvestigationNature' )
InvestigationConclusion = Actor.importLib( '../../utils/hcp_helpers', 'InvestigationConclusion' )

class SampleHunter ( Hunter ):
    detects = ( 'TestDetection', )

    def init( self, parameters, resources ):
        super( SampleHunter, self ).init( parameters )

    def investigate( self, investigation, detect ):
        source = detect[ 'source' ].split( ' / ' )[ 0 ]
        inv_id = detect[ 'detect_id' ]
        data = detect[ 'detect' ]
        pid = _x_( data, '?/base.PROCESS_ID' )

        memMapResp = investigation.task( 'looking for suspicious memory pages', 
                                         source, 
                                         ( 'mem_map', pid ) )

        if memMapResp.wait( 120 ):
            investigation.reportData( 'received the memory map', memMapResp.responses.pop() )
        else:
            investigation.reportData( 'failed to receive the memory map, sensor offline?' )

        investigation.conclude( 'this was a test detection and hunt',
                                InvestigationNature.TEST,
                                InvestigationConclusion.NO_ACTION_TAKEN )
