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
import hashlib
Hunt = Actor.importLib( '../../Hunts', 'Hunt' )
_xm_ = Actor.importLib( '../../hcp_helpers', '_xm_' )
_x_ = Actor.importLib( '../../hcp_helpers', '_x_' )
exeFromPath = Actor.importLib( '../../hcp_helpers', 'exeFromPath' )

class SuspectedDropperHunt ( Hunt ):
    detects = ( 'WinSuspExecName', )

    def init( self, parameters ):
        super( SuspectedDropperHunt, self ).init( parameters )

    def updateHunt( self, context, newMsg ):
        if newMsg is None:
            source = context[ 'source' ].split( ' / ' )[ 0 ]
            inv_id = context[ 'report_id' ]
            detect = context[ 'detect' ]
            pid = _x_( detect, '?/base.PROCESS_ID' )
            filePath = _x_( detect, '?/base.FILE_PATH' )
            fileName = exeFromPath( filePath )
            fileHash = _x_( detect, '?/base.HASH' )

            # Ok let's figure out if we've investigate this before
            isInvestigated = False
            resp = self.Models.request( 'get_kv', { 'cat' : 'inv_files', 'k' : fileHash } )
            isInvestigated = resp.isSuccess

            if not isInvestigated:
                resp = self.Models.request( 'get_kv', { 'cat' : 'inv_files', 'k' : fileName } )
                isInvestigated = resp.isSuccess

            if isInvestigated:
                return False

            self.task( source, ( ( 'mem_strings', pid ),
                                 ( 'file_get', filePath ),
                                 ( 'file_info', filePath ),
                                 ( 'history_dump', ),
                                 ( 'exfil_add', 'notification.FILE_CREATE', '--expire', 60 ),
                                 ( 'exfil_add', 'notification.FILE_DELETE', '--expire', 60 ),
                                 ( 'os_services', ),
                                 ( 'os_drivers', ),
                                 ( 'os_autoruns', ) ),
                               expiry = 60,
                               inv_id = inv_id )
        else:
            routing, event, mtd = newMsg
            source = context[ 'source' ].split( ' / ' )[ 0 ]
            # We tried to get the dropper, if we got the file record the metadata
            # in the KeyValue store so we don't get it multiple times.
            if 'notification.FILE_GET_REP' == routing[ 'event_type' ]:
                filePath = _x_( event, 'base.FILE_PATH' )
                fileContent = _x_( event, 'base.FILE_CONTENT' )
                if fileContent and 0 != len( fileContent ):
                    # We'll record that we investigated these
                    self.Models.request( 'set_kv', { 'cat' : 'droppers',
                                                     'k' : filePath,
                                                     'v' : filePath } )
                    self.Models.request( 'set_kv', { 'cat' : 'droppers',
                                                     'k' : hashlib.sha256( fileContent ).hexdigest(),
                                                     'v' : filePath } )
            elif routing[ 'event_type' ] in ( 'notification.OS_SERVICES_REP',
                                              'notification.OS_DRIVERS_REP',
                                              'notification.OS_AUTORUNS_REP' ):
                # We've gotten new snapshots from the system, let's see if something changed
                # which might be a persistence mechanism.
                changes = self.Models.request( 'get_host_changes', { 'id' : source } )
                if changes.isSuccess and 0 != len( changes.data[ 'changes' ] ):
                    context[ 'detect' ].setdefault( 'recent_changes', {} ).update( changes.data[ 'changes' ] )
                    self.postUpdatedDetect( context )


        # Keep this investigation alive
        return True

