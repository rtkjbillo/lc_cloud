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
import time_uuid
CassDb = Actor.importLib( '../utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( '../utils/hcp_databases', 'CassPool' )
CreateOnAccess = Actor.importLib( '../utils/hcp_helpers', 'CreateOnAccess' )

class AnalyticsReporting( Actor ):
    def init( self, parameters, resources ):
        self.ttl = parameters.get( 'ttl', ( 60 * 60 * 24 * 365 ) )
        self._db = CassDb( parameters[ 'db' ], 'hcp_analytics', consistencyOne = True )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )

        self.report_stmt_rep = self.db.prepare( 'INSERT INTO detects ( did, gen, source, dtype, events, detect, why ) VALUES ( ?, dateOf( now() ), ?, ?, ?, ?, ? ) USING TTL %d' % self.ttl )
        self.report_stmt_rep.consistency_level = CassDb.CL_Ingest

        self.report_stmt_tl = self.db.prepare( 'INSERT INTO detect_timeline ( d, ts, did ) VALUES ( ?, now(), ? ) USING TTL %d' % self.ttl )
        self.report_stmt_tl.consistency_level = CassDb.CL_Ingest

        self.new_inv_stmt = self.db.prepare( 'INSERT INTO investigation ( invid, gen, closed, nature, conclusion, why, hunter ) VALUES ( ?, ?, 0, 0, 0, \'\', ? ) USING TTL %d' % self.ttl )

        self.close_inv_stmt = self.db.prepare( 'UPDATE investigation USING TTL %d SET closed = ? WHERE invid = ? AND hunter = ?' % self.ttl )

        self.task_inv_stmt = self.db.prepare( 'INSERT INTO inv_task ( invid, gen, why, dest, data, sent, hunter ) VALUES ( ?, ?, ?, ?, ?, ?, ? ) USING TTL %d' % self.ttl )

        self.report_inv_stmt = self.db.prepare( 'INSERT INTO inv_data ( invid, gen, why, data, hunter ) VALUES ( ?, ?, ?, ?, ? ) USING TTL %d' % self.ttl )

        self.conclude_inv_stmt = self.db.prepare( 'UPDATE investigation USING TTL %s SET closed = ?, nature = ?, conclusion = ?, why = ?, hunter = ? WHERE invid = ?' % self.ttl )

        self.outputs = self.getActorHandleGroup( resources[ 'output' ] )

        self.db.start()
        self.handle( 'detect', self.detect )
        self.handle( 'new_inv', self.new_inv )
        self.handle( 'close_inv', self.close_inv )
        self.handle( 'inv_task', self.inv_task )
        self.handle( 'report_inv', self.report_inv )
        self.handle( 'conclude_inv', self.conclude_inv )

        self.paging = CreateOnAccess( self.getActorHandle, resources[ 'paging' ] )
        self.pageDest = parameters.get( 'paging_dest', [] )
        if type( self.pageDest ) is str or type( self.pageDest ) is unicode:
            self.pageDest = [ self.pageDest ]

    def deinit( self ):
        self.db.stop()
        self._db.shutdown()

    def detect( self, msg ):
        event_ids = msg.data[ 'msg_ids' ]
        category = msg.data[ 'cat' ]
        source = msg.data[ 'source' ]
        why = msg.data[ 'summary' ]
        detect = base64.b64encode( msgpack.packb( msg.data[ 'detect' ] ) )
        detect_id = msg.data[ 'detect_id' ].upper()

        self.db.execute_async( self.report_stmt_rep.bind( ( detect_id, source, category, ' / '.join( event_ids ), detect, why ) ) )
        self.db.execute_async( self.report_stmt_tl.bind( ( random.randint( 0, 255 ), detect_id ) ) )

        self.outputs.shoot( 'report', msg.data )

        if 0 != len( self.pageDest ):
            self.paging.shoot( 'page', { 'to' : self.pageDest,
                                         'msg' : json.dumps( msg.data[ 'detect' ], indent = 2 ),
                                         'subject' : 'Detect: %s/%s' % ( category, source ) } )

        return ( True, )

    def new_inv( self, msg ):
        invId = msg.data[ 'inv_id' ]
        ts = msg.data[ 'ts' ] * 1000
        detect = msg.data[ 'detect' ]
        hunter = msg.data[ 'hunter' ]

        self.db.execute( self.new_inv_stmt.bind( ( invId, ts, hunter ) ) )
        return ( True, )

    def close_inv( self, msg ):
        invId = msg.data[ 'inv_id' ]
        ts = msg.data[ 'ts' ] * 1000
        hunter = msg.data[ 'hunter' ]

        self.db.execute( self.close_inv_stmt.bind( ( ts, invId, hunter ) ) )
        return ( True, )

    def inv_task( self, msg ):
        invId = msg.data[ 'inv_id' ]
        ts = msg.data[ 'ts' ] * 1000
        task = msgpack.packb( msg.data[ 'task' ] )
        why = msg.data[ 'why' ]
        dest = msg.data[ 'dest' ]
        isSent = msg.data[ 'is_sent' ]
        hunter = msg.data[ 'hunter' ]

        self.db.execute( self.task_inv_stmt.bind( ( invId, time_uuid.TimeUUID.with_timestamp( ts ), why, dest, task, isSent, hunter ) ) )
        return ( True, )

    def report_inv( self, msg ):
        invId = msg.data[ 'inv_id' ]
        ts = msg.data[ 'ts' ] * 1000
        data = msgpack.packb( msg.data[ 'data' ] )
        why = msg.data[ 'why' ]
        hunter = msg.data[ 'hunter' ]

        self.db.execute( self.report_inv_stmt.bind( ( invId, time_uuid.TimeUUID.with_timestamp( ts ), why, data, hunter ) ) )
        return ( True, )

    def conclude_inv( self, msg ):
        invId = msg.data[ 'inv_id' ]
        ts = msg.data[ 'ts' ] * 1000
        why = msg.data[ 'why' ]
        nature = msg.data[ 'nature' ]
        conclusion = msg.data[ 'conclusion' ]
        hunter = msg.data[ 'hunter' ]

        self.db.execute( self.conclude_inv_stmt.bind( ( ts, nature, conclusion, why, invId, hunter ) ) )
        return ( True, )