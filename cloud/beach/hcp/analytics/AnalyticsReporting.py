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
import msgpack
import base64
import random
import json
CassDb = Actor.importLib( '../hcp_databases', 'CassDb' )
CassPool = Actor.importLib( '../hcp_databases', 'CassPool' )

class AnalyticsReporting( Actor ):
    def init( self, parameters ):
        self._db = CassDb( parameters[ 'db' ], 'hcp_analytics', consistencyOne = True )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )

        self.report_stmt_rep = self.db.prepare( 'INSERT INTO reports ( repid, gen, source, dtype, events, detect ) VALUES ( ?, dateOf( now() ), ?, ?, ?, ? ) USING TTL %d' % ( 60 * 60 * 24 * 7 * 4 ) )
        self.report_stmt_rep.consistency_level = CassDb.CL_Ingest

        self.report_stmt_tl = self.db.prepare( 'INSERT INTO report_timeline ( d, ts, repid ) VALUES ( ?, now(), ? ) USING TTL %d' % ( 60 * 60 * 24 * 7 * 4 ) )
        self.report_stmt_tl.consistency_level = CassDb.CL_Ingest

        self.db.start()
        self.handle( 'report', self.report )
        self.paging = self.getActorHandle( 'paging' )
        self.pageDest = parameters.get( 'paging_dest', [] )
        if type( self.pageDest ) is str or type( self.pageDest ) is unicode:
            self.pageDest = [ self.pageDest ]

    def deinit( self ):
        self.db.stop()
        self._db.shutdown()

    def report( self, msg ):
        event_ids = msg.data[ 'msg_ids' ]
        category = msg.data[ 'cat' ]
        source = msg.data[ 'source' ]
        detect = base64.b64encode( msgpack.packb( msg.data[ 'detect' ] ) )
        report_id = msg.data[ 'report_id' ].upper()

        self.db.execute_async( self.report_stmt_rep.bind( ( report_id, source, category, ' / '.join( event_ids ), detect ) ) )
        self.db.execute_async( self.report_stmt_tl.bind( ( random.randint( 0, 255 ), report_id ) ) )

        if 0 != len( self.pageDest ):
            self.paging.shoot( 'page', { 'to' : self.pageDest,
                                         'msg' : json.dumps( msg.data[ 'detect' ], indent = 2 ),
                                         'subject' : 'Detect: %s/%s' % ( category, source ) } )

        return ( True, )