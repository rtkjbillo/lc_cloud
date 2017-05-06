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
import time_uuid
import uuid
import base64
import msgpack
import datetime
import random
import traceback
from sets import Set
CassDb = Actor.importLib( '../utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( '../utils/hcp_databases', 'CassPool' )
AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )
_x_ = Actor.importLib( '../utils/hcp_helpers', '_x_' )
_xm_ = Actor.importLib( '../utils/hcp_helpers', '_xm_' )
ObjectTypes = Actor.importLib( '../utils/ObjectsDb', 'ObjectTypes' )
RelationName = Actor.importLib( '../utils/ObjectsDb', 'RelationName' )
ObjectKey = Actor.importLib( '../utils/ObjectsDb', 'ObjectKey' )

class AnalyticsModeling( Actor ):
    def init( self, parameters, resources ):
        self._db = CassDb( parameters[ 'db' ], 'hcp_analytics', consistencyOne = True )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )
        #self.db = self._db

        self.ignored_objects = [ ObjectTypes.STRING,
                                 ObjectTypes.IP_ADDRESS,
                                 ObjectTypes.MODULE_SIZE,
                                 ObjectTypes.STRING,
                                 ObjectTypes.THREADS,
                                 ObjectTypes.MEM_HEADER_HASH ]

        self.temporary_objects = [ ObjectTypes.CMD_LINE,
                                   ObjectTypes.DOMAIN_NAME,
                                   ObjectTypes.PORT ]

        self.org_ttls = {}
        if 'identmanager' in resources:
            self.identmanager = self.getActorHandle( resources[ 'identmanager' ] )
        else:
            self.identmanager = None
            self.log( 'using default ttls' )

        self.default_ttl_events = parameters[ 'retention_raw_events' ]
        self.default_ttl_long_obj = parameters[ 'retention_objects_primary' ]
        self.default_ttl_short_obj = parameters[ 'retention_objects_secondary' ]
        self.default_ttl_atoms = parameters[ 'retention_explorer' ]
        self.default_ttl_detections = parameters[ 'retention_investigations' ]

        self.stmt_events = self.ingestStatement( 'INSERT INTO events ( eventid, event, sid ) VALUES ( ?, ?, ? ) USING TTL ?' )
        self.stmt_timeline = self.ingestStatement( 'INSERT INTO timeline ( sid, ts, eventid, eventtype ) VALUES ( ?, ?, ?, ? ) USING TTL ?' )
        self.stmt_timeline_by_type = self.ingestStatement( 'INSERT INTO timeline_by_type ( sid, ts, eventid, eventtype ) VALUES ( ?, ?, ?, ? ) USING TTL ?' )
        self.stmt_recent = self.ingestStatement( 'UPDATE recentlyActive USING TTL ? SET last = dateOf( now() ) WHERE sid = ?' )
        self.stmt_last = self.ingestStatement( 'UPDATE last_events USING TTL ? SET id = ? WHERE sid = ? AND type = ?' )
        self.stmt_investigation = self.ingestStatement( 'INSERT INTO investigation_data ( invid, ts, eid, etype ) VALUES ( ?, ?, ?, ? ) USING TTL ?' )
        self.stmt_rel_batch_parent = self.ingestStatement( 'INSERT INTO rel_man_parent ( parentkey, ctype, cid ) VALUES ( ?, ?, ? ) USING TTL ?' )
        self.stmt_rel_batch_child = self.ingestStatement( 'INSERT INTO rel_man_child ( childkey, ptype, pid ) VALUES ( ?, ?, ? ) USING TTL ?' )
        self.stmt_obj_batch_man = self.ingestStatement( 'INSERT INTO obj_man ( id, obj, otype ) VALUES ( ?, ?, ? ) USING TTL ?' )
        self.stmt_obj_batch_loc = self.ingestStatement( 'UPDATE loc USING TTL ? SET last = ? WHERE sid = ? AND otype = ? AND id = ?' )
        self.stmt_obj_batch_id = self.ingestStatement( 'INSERT INTO loc_by_id ( id, sid, last ) VALUES ( ?, ?, ? ) USING TTL ?' )
        self.stmt_obj_batch_type = self.ingestStatement( 'INSERT INTO loc_by_type ( d256, otype, id, sid ) VALUES ( ?, ?, ?, ? ) USING TTL ?' )
        self.stmt_obj_org = self.ingestStatement( 'INSERT INTO obj_org ( id, oid ) VALUES ( ?, ? ) USING TTL ?' )

        self.stmt_atoms_children = self.ingestStatement( 'INSERT INTO atoms_children ( atomid, child, eid ) VALUES ( ?, ?, ? ) USING TTL ?' )
        self.stmt_atoms_lookup = self.ingestStatement( 'INSERT INTO atoms_lookup ( atomid, eid ) VALUES ( ?, ? ) USING TTL ?' )

        self.db.start()
        self.processedCounter = 0
        self.handle( 'analyze', self.analyze )

    def deinit( self ):
        self.db.stop()
        self._db.shutdown()

    def ingestStatement( self, statement ):
        stmt = self.db.prepare( statement )
        stmt.consistency_level = CassDb.CL_Ingest
        return stmt

    def getOrgTtls( self, oid ):
        ttls = None
        
        if self.identmanager is not None:
            ttls = self.org_ttls.get( oid, None )
            if ttls is None:
                res = self.identmanager.request( 'get_org_info', { 'oid' : oid } )
                if res.isSuccess and 0 != len( res.data[ 'orgs' ] ):
                    self.org_ttls[ oid ] = res.data[ 'orgs' ][ 0 ][ 2 ]
                    ttls = self.org_ttls[ oid ]
                    self.log( 'using custom ttls for %s' % oid )
        
        if ttls is None:
            ttls = { 'events' : self.default_ttl_events,
                     'long_obj' : self.default_ttl_long_obj,
                     'short_obj' : self.default_ttl_short_obj,
                     'atoms' : self.default_ttl_atoms,
                     'detections' : self.default_ttl_detections }
        return ttls

    def _ingestObjects( self, ttls, sid, ts, objects, relations, oid ):
        ts = datetime.datetime.fromtimestamp( ts )

        for relType, relVals in relations.iteritems():
            for relVal in relVals:
                objects.setdefault( ObjectTypes.RELATION, [] ).append( RelationName( relVal[ 0 ],
                                                                                     relType[ 0 ],
                                                                                     relVal[ 1 ],
                                                                                     relType[ 1 ] ) )

                if relType[ 0 ] in self.temporary_objects or relType[ 1 ] in self.temporary_objects:
                    ttl = ttls[ 'short_obj' ]
                else:
                    ttl = ttls[ 'long_obj' ]

                self.db.execute_async( self.stmt_rel_batch_parent.bind( ( ObjectKey( relVal[ 0 ], relType[ 0 ] ),
                                                                          relType[ 1 ],
                                                                          ObjectKey( relVal[ 1 ], relType[ 1 ] ),
                                                                          ttl ) ) )

                self.db.execute_async( self.stmt_rel_batch_child.bind( ( ObjectKey( relVal[ 1 ], relType[ 1 ] ),
                                                                         relType[ 0 ],
                                                                         ObjectKey( relVal[ 0 ], relType[ 0 ] ),
                                                                         ttl ) ) )

        for objType, objVals in objects.iteritems():
            for objVal in objVals:
                k = ObjectKey( objVal, objType )

                if objType in self.temporary_objects:
                    ttl = ttls[ 'short_obj' ]
                else:
                    ttl = ttls[ 'long_obj' ]

                self.db.execute_async( self.stmt_obj_batch_man.bind( ( k, objVal, objType, ttl ) ) )
                self.db.execute_async( self.stmt_obj_org.bind( ( k, oid, ttl ) ) )
                self.db.execute_async( self.stmt_obj_batch_loc.bind( ( ttl, ts, sid, objType, k ) ) )
                self.db.execute_async( self.stmt_obj_batch_id.bind( ( k, sid, ts, ttl ) ) )
                self.db.execute_async( self.stmt_obj_batch_type.bind( ( random.randint( 0, 256 ), objType, k, sid, ttl ) ) )


    def analyze( self, msg ):
        routing, event, mtd = msg.data

        self.processedCounter += 1

        if 0 == ( self.processedCounter % 1000 ):
            self.log( 'MOD_IN %s' % self.processedCounter )
            if 0 == ( self.processedCounter % 5000 ):
                self.org_ttls = {}

        agent = AgentId( routing[ 'aid' ] )
        sid = agent.sensor_id
        ts = _x_( event, '?/base.TIMESTAMP' )

        ttls = self.getOrgTtls( agent.org_id )

        if ts is not None:
            ts = float( ts ) / 1000

        if ts is None or ts > ( 2 * time.time() ):
            ts = _x_( event, 'base.TIMESTAMP' )
            if ts is None:
                ts = time_uuid.utctime()
            else:
                ts = float( ts ) / 1000

        eid = uuid.UUID( routing[ 'event_id' ] )

        self.db.execute_async( self.stmt_events.bind( ( eid,
                                                        base64.b64encode( msgpack.packb( { 'routing' : routing, 'event' : event } ) ),
                                                        sid,
                                                        ttls[ 'events' ] ) ) )

        self.db.execute_async( self.stmt_timeline.bind( ( sid,
                                                          time_uuid.TimeUUID.with_timestamp( ts ),
                                                          eid,
                                                          routing[ 'event_type' ],
                                                          ttls[ 'events' ] ) ) )

        self.db.execute_async( self.stmt_timeline_by_type.bind( ( sid,
                                                                  time_uuid.TimeUUID.with_timestamp( ts ),
                                                                  eid,
                                                                  routing[ 'event_type' ],
                                                                  ttls[ 'events' ] ) ) )

        self.db.execute_async( self.stmt_recent.bind( ( ttls[ 'events' ], sid, ) ) )

        self.db.execute_async( self.stmt_last.bind( ( ttls[ 'events' ],
                                                      eid,
                                                      sid,
                                                      routing[ 'event_type' ] ) ) )

        this_atom = _x_( event, '?/hbs.THIS_ATOM' )
        parent_atom = _x_( event, '?/hbs.PARENT_ATOM' )
        null_atom = "\x00" * 16

        if this_atom is not None:
            if this_atom == null_atom:
                this_atom = None
            else:
                try:
                    this_atom = uuid.UUID( bytes = str( this_atom ) )
                except:
                    self.log( 'invalid atom: %s / %s ( %s )' % ( this_atom, type( this_atom ), traceback.format_exc() ) )
                    this_atom = None

        if parent_atom is not None:
            if parent_atom == null_atom:
                parent_atom = None
            else:
                try:
                    parent_atom = uuid.UUID( bytes = str( parent_atom ) )
                except:
                    self.log( 'invalid atom: %s / %s ( %s )' % ( parent_atom, type( parent_atom ), traceback.format_exc() ) )
                    parent_atom = None

        if this_atom is not None:
            self.db.execute_async( self.stmt_atoms_lookup.bind( ( this_atom,
                                                                  eid,
                                                                  ttls[ 'atoms' ] ) ) )

        if this_atom is not None and parent_atom is not None:
            self.db.execute_async( self.stmt_atoms_children.bind( ( parent_atom,
                                                                    this_atom if this_atom is not None else uuid.UUID( bytes = null_atom ),
                                                                    eid,
                                                                    ttls[ 'atoms' ] ) ) )

        inv_id = _x_( event, '?/hbs.INVESTIGATION_ID' )
        if inv_id is not None and inv_id != '':
            self.db.execute_async( self.stmt_investigation.bind( ( inv_id.upper().split( '//' )[ 0 ],
                                                                   time_uuid.TimeUUID.with_timestamp( ts ),
                                                                   eid,
                                                                   routing[ 'event_type' ],
                                                                   ttls[ 'detections' ] ) ) )
        new_objects = mtd[ 'obj' ]
        new_relations = mtd[ 'rel' ]

        for ignored in self.ignored_objects:
            if ignored in new_objects:
                del( new_objects[ ignored ] )
            for k in new_relations.keys():
                if ignored in k:
                    del( new_relations[ k ] )

        if 0 != len( new_objects ) or 0 != len( new_relations ):
            self._ingestObjects( ttls, sid, ts, new_objects, new_relations, agent.org_id )
        #self.log( 'finished storing objects %s: %s / %s' % ( routing[ 'event_type' ], len( new_objects ), len( new_relations )) )
        return ( True, )
