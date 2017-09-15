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
import json
import time_uuid
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )
CassDb = Actor.importLib( '../utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( '../utils/hcp_databases', 'CassPool' )
CreateOnAccess = Actor.importLib( '../utils/hcp_helpers', 'CreateOnAccess' )

class AnalyticsReporting( Actor ):
    def init( self, parameters, resources ):
        self._db = CassDb( parameters[ 'db' ], 'hcp_analytics', consistencyOne = True )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )

        self.report_stmt_rep = self.db.prepare( 'INSERT INTO detects ( did, gen, source, dtype, events, detect, why ) VALUES ( ?, dateOf( now() ), ?, ?, ?, ?, ? ) USING TTL ?' )
        self.report_stmt_rep.consistency_level = CassDb.CL_Ingest

        self.report_stmt_tl = self.db.prepare( 'INSERT INTO detect_timeline ( oid, ts, did ) VALUES ( ?, now(), ? ) USING TTL ?' )
        self.report_stmt_tl.consistency_level = CassDb.CL_Ingest

        self.new_inv_stmt = self.db.prepare( 'INSERT INTO investigation ( invid, gen, closed, nature, conclusion, why, hunter ) VALUES ( ?, ?, 0, 0, 0, \'\', ? ) USING TTL ?' )

        self.close_inv_stmt = self.db.prepare( 'UPDATE investigation USING TTL ? SET closed = ? WHERE invid = ? AND hunter = ?' )

        self.task_inv_stmt = self.db.prepare( 'INSERT INTO inv_task ( invid, gen, why, dest, data, sent, hunter ) VALUES ( ?, ?, ?, ?, ?, ?, ? ) USING TTL ?' )

        self.report_inv_stmt = self.db.prepare( 'INSERT INTO inv_data ( invid, gen, why, data, hunter ) VALUES ( ?, ?, ?, ?, ? ) USING TTL ?' )

        self.conclude_inv_stmt = self.db.prepare( 'UPDATE investigation USING TTL ? SET closed = ?, nature = ?, conclusion = ?, why = ? WHERE invid = ? AND hunter = ?' )

        self.set_inv_nature_stmt = self.db.prepare( 'UPDATE investigation USING TTL ? SET nature = ? WHERE invId = ? AND hunter = ?' )
        self.set_inv_conclusion_stmt = self.db.prepare( 'UPDATE investigation USING TTL ? SET conclusion = ? WHERE invId = ? AND hunter = ?' )

        self.get_detect_source_stmt = self.db.prepare( 'SELECT source FROM detects WHERE did = ?' )

        self.outputs = self.getActorHandleGroup( resources[ 'output' ], timeout = 30, nRetries = 3 )

        self.default_ttl_detections = parameters.get( 'retention_investigations', 60 * 60 * 24 * 365 )
        self.org_ttls = {}
        if 'identmanager' in resources:
            self.identmanager = self.getActorHandle( resources[ 'identmanager' ], timeout = 30, nRetries = 3 )
        else:
            self.identmanager = None
            self.log( 'using default ttls' )

        self.db.start()
        self.handle( 'detect', self.detect )
        self.handle( 'new_inv', self.new_inv )
        self.handle( 'close_inv', self.close_inv )
        self.handle( 'inv_task', self.inv_task )
        self.handle( 'report_inv', self.report_inv )
        self.handle( 'conclude_inv', self.conclude_inv )
        self.handle( 'set_inv_nature', self.set_inv_nature )
        self.handle( 'set_inv_conclusion', self.set_inv_conclusion )

        self.paging = CreateOnAccess( self.getActorHandle, resources[ 'paging' ], timeout = 30, nRetries = 2 )
        self.pageDest = parameters.get( 'paging_dest', [] )
        if type( self.pageDest ) is str or type( self.pageDest ) is unicode:
            self.pageDest = [ self.pageDest ]

        self.model = CreateOnAccess( self.getActorHandle, resources[ 'modeling' ], timeout = 30, nRetries = 2 )

    def deinit( self ):
        self.db.stop()
        self._db.shutdown()

    def getOrgTtl( self, oid ):
        ttl = None
        
        if self.identmanager is not None:
            ttl = self.org_ttls.get( oid, None )
            if ttl is None:
                res = self.identmanager.request( 'get_org_info', { 'oid' : oid } )
                if res.isSuccess and 0 != len( res.data[ 'orgs' ] ):
                    self.org_ttls[ oid ] = res.data[ 'orgs' ][ 0 ][ 2 ][ 'detections' ]
                    ttl = self.org_ttls[ oid ]
                    self.log( 'using custom ttl for %s' % oid )
        
        if ttl is None:
            ttl = self.default_ttl_detections
        return ttl

    def getDetectSource( self, did ):
        source = None
        nRetries = 3
        while source is None:
            for detect in self.db.execute( self.get_detect_source_stmt.bind( ( did, ) ) ):
                source = detect[ 0 ]
                break
            if 0 == nRetries:
                break
            nRetries -= 1
            self.sleep( 1 )
        return source

    def detect( self, msg ):
        event_ids = msg.data[ 'msg_ids' ]
        category = msg.data[ 'cat' ]
        source = msg.data[ 'source' ]
        why = msg.data[ 'summary' ]
        detect = base64.b64encode( msgpack.packb( msg.data[ 'detect' ] ) )
        detect_id = msg.data[ 'detect_id' ].upper()
        oid = AgentId( source.split( ' / ' )[ 0 ] ).org_id

        try:
            self.db.execute_async( self.report_stmt_rep.bind( ( detect_id, source, category, ' / '.join( event_ids ), detect, why, self.getOrgTtl( oid ) ) ) )
            for s in source.split( ' / ' ):
                self.db.execute_async( self.report_stmt_tl.bind( ( AgentId( s ).org_id, detect_id, self.getOrgTtl( oid ) ) ) )
        except:
            import traceback
            self.logCritical( 'Exc storing detect %s / %s' % ( str( msg.data ), traceback.format_exc() ) )
        self.outputs.shoot( 'report_detect', msg.data )

        if 0 != len( self.pageDest ):
            self.paging.shoot( 'page', { 'to' : self.pageDest,
                                         'msg' : json.dumps( msg.data[ 'detect' ], indent = 2 ),
                                         'subject' : 'Detect: %s/%s' % ( category, source ) } )

        return ( True, )

    def new_inv( self, msg ):
        invId = msg.data[ 'inv_id' ].upper()
        ts = msg.data[ 'ts' ] * 1000
        detect = msg.data[ 'detect' ]
        hunter = msg.data[ 'hunter' ]
        source = self.getDetectSource( invId )
        oid = AgentId( source.split( ' / ' )[ 0 ] ).org_id

        self.db.execute( self.new_inv_stmt.bind( ( invId, ts, hunter, self.getOrgTtl( oid ) ) ) )
        return ( True, )

    def close_inv( self, msg ):
        invId = msg.data[ 'inv_id' ].upper()
        ts = msg.data[ 'ts' ] * 1000
        hunter = msg.data[ 'hunter' ]
        source = self.getDetectSource( invId )
        oid = AgentId( source.split( ' / ' )[ 0 ] ).org_id

        self.db.execute( self.close_inv_stmt.bind( ( self.getOrgTtl( oid ), ts, invId, hunter ) ) )

        info = self.model.request( 'get_detect', { 'id' : invId, 'with_inv' : True } )
        investigations = []
        if info.isSuccess:
            investigations = info.data[ 'inv' ].values()
        for inv in investigations:
            if inv[ 'hunter' ] == hunter:
                inv[ 'source' ] = source
                inv[ 'inv_id' ] = invId
                self.outputs.shoot( 'report_inv', inv )
                break

        return ( True, )

    def inv_task( self, msg ):
        invId = msg.data[ 'inv_id' ].upper()
        ts = msg.data[ 'ts' ]
        task = base64.b64encode( msgpack.packb( msg.data[ 'task' ] ) )
        why = msg.data[ 'why' ]
        dest = msg.data[ 'dest' ]
        isSent = msg.data[ 'is_sent' ]
        hunter = msg.data[ 'hunter' ]
        source = self.getDetectSource( invId )
        oid = AgentId( source.split( ' / ' )[ 0 ] ).org_id

        self.db.execute( self.task_inv_stmt.bind( ( invId, time_uuid.TimeUUID.with_timestamp( ts ), why, dest, task, isSent, hunter, self.getOrgTtl( oid ) ) ) )
        return ( True, )

    def report_inv( self, msg ):
        invId = msg.data[ 'inv_id' ].upper()
        ts = msg.data[ 'ts' ]
        data = base64.b64encode( msgpack.packb( msg.data[ 'data' ] ) )
        why = msg.data[ 'why' ]
        hunter = msg.data[ 'hunter' ]
        source = self.getDetectSource( invId )
        oid = AgentId( source.split( ' / ' )[ 0 ] ).org_id

        self.db.execute( self.report_inv_stmt.bind( ( invId, time_uuid.TimeUUID.with_timestamp( ts ), why, data, hunter, self.getOrgTtl( oid ) ) ) )
        return ( True, )

    def conclude_inv( self, msg ):
        invId = msg.data[ 'inv_id' ].upper()
        ts = msg.data[ 'ts' ] * 1000
        why = msg.data[ 'why' ]
        nature = msg.data[ 'nature' ]
        conclusion = msg.data[ 'conclusion' ]
        hunter = msg.data[ 'hunter' ]
        source = self.getDetectSource( invId )
        oid = AgentId( source.split( ' / ' )[ 0 ] ).org_id

        self.db.execute( self.conclude_inv_stmt.bind( ( self.getOrgTtl( oid ), ts, nature, conclusion, why, invId, hunter ) ) )
        return ( True, )

    def set_inv_nature( self, msg ):
        invId = msg.data[ 'inv_id' ].upper()
        hunter = msg.data[ 'hunter' ]
        nature = msg.data[ 'nature' ]
        source = self.getDetectSource( invId )
        oid = AgentId( source.split( ' / ' )[ 0 ] ).org_id

        self.db.execute( self.set_inv_nature_stmt.bind( ( self.getOrgTtl( oid ), nature, invId, hunter ) ) )
        return ( True, )

    def set_inv_conclusion( self, msg ):
        invId = msg.data[ 'inv_id' ].upper()
        hunter = msg.data[ 'hunter' ]
        conclusion = msg.data[ 'conclusion' ]
        source = self.getDetectSource( invId )
        oid = AgentId( source.split( ' / ' )[ 0 ] ).org_id

        self.db.execute( self.set_inv_conclusion_stmt.bind( ( self.getOrgTtl( oid ), conclusion, invId, hunter ) ) )
        return ( True, )