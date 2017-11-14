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
import os
import json
import logging
import logging.handlers
import random
import traceback
from sets import Set
import boto3
import tempfile
AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )
_x_ = Actor.importLib( '../utils/hcp_helpers', '_x_' )
_xm_ = Actor.importLib( '../utils/hcp_helpers', '_xm_' )
Mutex = Actor.importLib( '../utils/hcp_helpers', 'Mutex' )
ObjectTypes = Actor.importLib( '../utils/ObjectsDb', 'ObjectTypes' )
RelationName = Actor.importLib( '../utils/ObjectsDb', 'RelationName' )
ObjectKey = Actor.importLib( '../utils/ObjectsDb', 'ObjectKey' )

class StorageCoProcessor( object ):
    def init( self, parameters, resources, fromActor ):
        self._actor = fromActor
        self.modelingLevel = 10
        self._use_b64 = False
        self._is_flat = False
        self.loggingDir = ''
        self.file_logger = None
        self.s3Bucket = ''
        self.awsKeyId = ''
        self.awsSecretKeyId = ''
        self.s3 = None
        self.s3TmpHandle = None
        self.s3Mutex = Mutex()
        self._actor.schedule( 60 * 1, self.s3Sync )
        self.deploymentmanager = self._actor.getActorHandle( resources[ 'deployment' ], timeout = 30, nRetries = 3 )
        self._actor.schedule( 60 * 5, self.refreshConfigs )

        self.ignored_objects = [ ObjectTypes.STRING,
                                 ObjectTypes.IP_ADDRESS,
                                 ObjectTypes.MODULE_SIZE,
                                 ObjectTypes.STRING,
                                 ObjectTypes.THREADS,
                                 ObjectTypes.MEM_HEADER_HASH,
                                 ObjectTypes.DOMAIN_NAME ]

        self.temporary_objects = [ ObjectTypes.PORT ]

        self.org_ttls = {}
        if 'identmanager' in resources:
            self.identmanager = self._actor.getActorHandle( resources[ 'identmanager' ], timeout = 10, nRetries = 3 )
        else:
            self.identmanager = None
            self._actor.log( 'using default ttls' )

        self.default_ttl_events = parameters[ 'retention_raw_events' ]
        self.default_ttl_long_obj = parameters[ 'retention_objects_primary' ]
        self.default_ttl_short_obj = parameters[ 'retention_objects_secondary' ]
        self.default_ttl_atoms = parameters[ 'retention_explorer' ]
        self.default_ttl_detections = parameters[ 'retention_investigations' ]

        self.stmt_events = self.ingestStatement( 'INSERT INTO events ( eventid, event, sid ) VALUES ( ?, ?, ? ) USING TTL ?' )
        self.stmt_timeline = self.ingestStatement( 'INSERT INTO timeline ( sid, ts, eventid, eventtype ) VALUES ( ?, ?, ?, ? ) USING TTL ?' )
        self.stmt_timeline_by_type = self.ingestStatement( 'INSERT INTO timeline_by_type ( sid, ts, eventid, eventtype ) VALUES ( ?, ?, ?, ? ) USING TTL ?' )
        self.stmt_last = self.ingestStatement( 'UPDATE last_events USING TTL ? SET id = ? WHERE sid = ? AND type = ?' )
        self.stmt_investigation = self.ingestStatement( 'INSERT INTO investigation_data ( invid, ts, eid, etype ) VALUES ( ?, ?, ?, ? ) USING TTL ?' )
        self.stmt_rel_batch_parent = self.ingestStatement( 'INSERT INTO rel_man_parent ( parentkey, ctype, cid ) VALUES ( ?, ?, ? ) USING TTL ?' )
        self.stmt_rel_batch_child = self.ingestStatement( 'INSERT INTO rel_man_child ( childkey, ptype, pid ) VALUES ( ?, ?, ? ) USING TTL ?' )
        self.stmt_obj_batch_man = self.ingestStatement( 'INSERT INTO obj_man ( id, obj, otype ) VALUES ( ?, ?, ? ) USING TTL ?' )
        self.stmt_obj_batch_loc = self.ingestStatement( 'UPDATE loc USING TTL ? SET last = ? WHERE sid = ? AND otype = ? AND id = ?' )
        self.stmt_obj_batch_id = self.ingestStatement( 'INSERT INTO loc_by_id ( id, sid, last ) VALUES ( ?, ?, ? ) USING TTL ?' )
        self.stmt_obj_batch_type = self.ingestStatement( 'INSERT INTO loc_by_type ( d256, otype, id, sid ) VALUES ( ?, ?, ?, ? ) USING TTL ?' )
        self.stmt_obj_org = self.ingestStatement( 'INSERT INTO obj_org ( id, oid, ts, sid, eid ) VALUES ( ?, ?, ?, ?, ? ) USING TTL ?' )

        self.stmt_atoms_children = self.ingestStatement( 'INSERT INTO atoms_children ( atomid, child, eid ) VALUES ( ?, ?, ? ) USING TTL ?' )
        self.stmt_atoms_lookup = self.ingestStatement( 'INSERT INTO atoms_lookup ( atomid, eid ) VALUES ( ?, ? ) USING TTL ?' )

        self.stmt_detect_report = self.ingestStatement( 'INSERT INTO detects ( did, gen, source, dtype, events, detect, why ) VALUES ( ?, dateOf( now() ), ?, ?, ?, ?, ? ) USING TTL ?' )

        self.nWrites = 0
        self.lastReport = time.time()
        self._actor.handle( 'report_detect', self.reportDetectOrInv )
        self._actor.schedule( 600, self.reportStats )
        self._actor.schedule( 60 * 5, self.resetTtls )

        return self

    def deinit( self ):
        pass

    def process( self, routing, event, mtd ):
        if 0 < self.modelingLevel:
            self.model( routing, event, mtd )
            self._actor.zInc( 'n_modeled' )
        if '' != self.loggingDir:
            self.logToDisk( routing, event, mtd )
            self._actor.zInc( 'n_logged' )
        if '' != self.s3Bucket:
            self.logToS3( routing, event, mtd )
            self._actor.zInc( 'n_uploaded_s3' )

    def refreshConfigs( self ):
        resp = self.deploymentmanager.request( 'get_global_config', {} )
        if not resp.isSuccess:
            self._actor.logCritical( "could not get global configs: %s" % resp )
        elif 'global/modeling_level' not in resp.data:
            self._actor.log( "modeling level config not set, assuming full" )
        else:
            if self.modelingLevel != resp.data[ 'global/modeling_level' ]:
                self.modelingLevel = resp.data[ 'global/modeling_level' ]
                self._actor.zSet( 'modeling_level', self.modelingLevel )
                self._actor.log( "modeling level changed to: %s" % self.modelingLevel )

        if self.loggingDir != resp.data[ 'global/logging_dir' ]:
            if '' == resp.data[ 'global/logging_dir' ]:
                self.loggingDir = ''
                self.file_logger = None
            else:
                if not os.path.exists( resp.data[ 'global/logging_dir' ] ):
                    self._actor.log( 'output directory does not exist, creating it' )
                    os.makedirs( resp.data[ 'global/logging_dir' ] )
                self.file_logger = logging.getLogger( 'limacharlie_events_file' )
                self.file_logger.propagate = False
                handler = logging.handlers.RotatingFileHandler( os.path.join( resp.data[ 'global/logging_dir' ], self._actor.name ), 
                                                                maxBytes = resp.data.get( 'global/logging_dir_max_bytes', 1024 * 1024 * 5 ), 
                                                                backupCount = resp.data.get( 'global/logging_dir_backup_count', 20 ) )
                handler.setFormatter( logging.Formatter( "%(message)s" ) )
                self.file_logger.setLevel( logging.INFO )
                self.file_logger.addHandler( handler )

                self._is_flat = resp.data.get( 'global/logging_dir_is_flat', False )
                self._use_b64 = resp.data.get( 'global/logging_dir_use_b64', False )

                self._actor.log( "logging directory changed from %s to %s" % ( self.loggingDir, resp.data[ 'global/logging_dir' ] ) )
                self.loggingDir = resp.data[ 'global/logging_dir' ]
                self._actor.zSet( 'logging_dir', self.loggingDir )

        if ( ( self.s3Bucket != resp.data[ 'global/s3_bucket' ] ) or 
             ( self.awsKeyId != resp.data[ 'global/aws_key_id' ] ) or 
             ( self.awsSecretKeyId != resp.data[ 'global/aws_secret_key_id' ] ) ):
            if '' == resp.data[ 'global/s3_bucket' ]:
                self.s3Bucket = ''
                self.s3 = None
            else:
                self.awsKeyId = resp.data[ 'global/aws_key_id' ]
                self.awsSecretKeyId = resp.data[ 'global/aws_secret_key_id' ]

                self.s3 = boto3.client('s3', 
                                       aws_secret_access_key = self.awsSecretKeyId, 
                                       aws_access_key_id = self.awsKeyId)

                if self.s3TmpHandle is None:
                    with self.s3Mutex:
                        toSend = self.s3TmpHandle
                        self.s3TmpHandle = tempfile.NamedTemporaryFile( mode = 'w+b' )

                self._actor.log( "s3 bucket changed from %s to %s" % ( self.s3Bucket, resp.data[ 'global/s3_bucket' ] ) )
                self.s3Bucket = resp.data[ 'global/s3_bucket' ]
                self._actor.zSet( 's3_bucket', self.s3Bucket )

    ###########################################################################
    #   MODELING
    ###########################################################################
    def resetTtls( self, ):
        self.org_ttls = {}

    def logDroppedInsert( self, query, params ):
        self._actor.logCritical( "Dropped Insert: %s // %s" % ( query, params ) )
        self._actor.delay( 60, self._actor.db.execute_async, query, failureCallback = self.logDroppedInsert )

    def asyncInsert( self, boundStatement ):
        self._actor.db.execute_async( boundStatement, failureCallback = self.logDroppedInsert )

    def reportStats( self ):
        now = time.time()
        enPerSec = float( self.nWrites ) / ( now - self.lastReport )
        wrPerSec = float( self._actor.db.nSuccess ) / ( now - self.lastReport )
        self._actor.log( "Enqueued/sec: %s, Write/sec: %s" % ( enPerSec, wrPerSec ) )
        self.nWrites = 0
        self._actor.db.nSuccess = 0
        self.lastReport = now
        self._actor.zSet( 'enqueue_per_sec', enPerSec )
        self._actor.zSet( 'write_per_sec', wrPerSec )
        self._actor.zInc( 'inserts_dropped', self._actor.db.nErrors )
        if 0 != self._actor.db.nErrors:
            self._actor.log( "Inserts dropped since last report: %s" % self._actor.db.nErrors )
            self._actor.db.nErrors = 0
        

    def ingestStatement( self, statement ):
        stmt = self._actor.db.prepare( statement )
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
                    self._actor.log( 'using custom ttls for %s' % oid )
        
        if ttls is None:
            ttls = { 'events' : self.default_ttl_events,
                     'long_obj' : self.default_ttl_long_obj,
                     'short_obj' : self.default_ttl_short_obj,
                     'atoms' : self.default_ttl_atoms,
                     'detections' : self.default_ttl_detections }
            self.org_ttls[ oid ] = ttls
        return ttls

    def _sanitizeData( self, obj ):
        if isinstance( obj, datetime.datetime ):
            return obj.strftime( '%Y-%m-%d %H:%M:%S' )
        else:
            return str( obj )

    def _ingestObjects( self, ttls, sid, ts, objects, relations, oid, eid ):
        ts = datetime.datetime.fromtimestamp( ts )

        if 10 <= self.modelingLevel:
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

                    self.asyncInsert( self.stmt_rel_batch_parent.bind( ( ObjectKey( relVal[ 0 ], relType[ 0 ] ),
                                                                         relType[ 1 ],
                                                                         ObjectKey( relVal[ 1 ], relType[ 1 ] ),
                                                                         ttl ) ) )

                    self.asyncInsert( self.stmt_rel_batch_child.bind( ( ObjectKey( relVal[ 1 ], relType[ 1 ] ),
                                                                        relType[ 0 ],
                                                                        ObjectKey( relVal[ 0 ], relType[ 0 ] ),
                                                                        ttl ) ) )
                    self.nWrites += 2

        if 7 <= self.modelingLevel:
            for objType, objVals in objects.iteritems():
                for objVal in objVals:
                    k = ObjectKey( objVal, objType )

                    if objType in self.temporary_objects:
                        ttl = ttls[ 'short_obj' ]
                    else:
                        ttl = ttls[ 'long_obj' ]

                    self.asyncInsert( self.stmt_obj_batch_man.bind( ( k, objVal, objType, ttl ) ) )
                    self.asyncInsert( self.stmt_obj_org.bind( ( k, oid, ts, sid, eid, min( ttl, ttls[ 'events' ] ) ) ) )
                    self.asyncInsert( self.stmt_obj_batch_loc.bind( ( ttl, ts, sid, objType, k ) ) )
                    self.asyncInsert( self.stmt_obj_batch_id.bind( ( k, sid, ts, ttl ) ) )
                    self.nWrites += 4
                    if 8 <= self.modelingLevel:
                        self.asyncInsert( self.stmt_obj_batch_type.bind( ( random.randint( 0, 256 ), objType, k, sid, ttl ) ) )
                        self.nWrites += 1


    def model( self, routing, event, mtd ):
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

        eid = routing[ 'event_id' ]

        if 1 < self.modelingLevel:
            self.asyncInsert( self.stmt_events.bind( ( eid,
                                                       base64.b64encode( msgpack.packb( { 'routing' : routing, 'event' : event }, 
                                                                                        default = self._sanitizeData ) ),
                                                       sid,
                                                       ttls[ 'events' ] ) ) )

            self.asyncInsert( self.stmt_timeline.bind( ( sid,
                                                         time_uuid.TimeUUID.with_timestamp( ts ),
                                                         eid,
                                                         routing[ 'event_type' ],
                                                         ttls[ 'events' ] ) ) )
            self.nWrites += 2

        self.asyncInsert( self.stmt_timeline_by_type.bind( ( sid,
                                                             time_uuid.TimeUUID.with_timestamp( ts ),
                                                             eid,
                                                             routing[ 'event_type' ],
                                                             ttls[ 'events' ] ) ) )
        self.nWrites += 1

        if 2 <= self.modelingLevel:
            self.asyncInsert( self.stmt_last.bind( ( ttls[ 'events' ],
                                                     eid,
                                                     sid,
                                                     routing[ 'event_type' ] ) ) )
            self.nWrites += 1

        if 5 <= self.modelingLevel:
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
                        self._actor.log( 'invalid atom: %s / %s ( %s )' % ( this_atom, type( this_atom ), traceback.format_exc() ) )
                        this_atom = None

            if parent_atom is not None:
                if parent_atom == null_atom:
                    parent_atom = None
                else:
                    try:
                        parent_atom = uuid.UUID( bytes = str( parent_atom ) )
                    except:
                        self._actor.log( 'invalid atom: %s / %s ( %s )' % ( parent_atom, type( parent_atom ), traceback.format_exc() ) )
                        parent_atom = None

            if this_atom is not None:
                self.asyncInsert( self.stmt_atoms_lookup.bind( ( this_atom,
                                                                 eid,
                                                                 ttls[ 'atoms' ] ) ) )
                self.nWrites += 1

            if this_atom is not None and parent_atom is not None:
                self.asyncInsert( self.stmt_atoms_children.bind( ( parent_atom,
                                                                   this_atom if this_atom is not None else uuid.UUID( bytes = null_atom ),
                                                                   eid,
                                                                   ttls[ 'atoms' ] ) ) )
                self.nWrites += 1

        if 2 <= self.modelingLevel:
            inv_id = _x_( event, '?/hbs.INVESTIGATION_ID' )
            if inv_id is not None and inv_id != '':
                self.asyncInsert( self.stmt_investigation.bind( ( inv_id.upper().split( '//' )[ 0 ],
                                                                  time_uuid.TimeUUID.with_timestamp( ts ),
                                                                  eid,
                                                                  routing[ 'event_type' ],
                                                                  ttls[ 'detections' ] ) ) )
                self.nWrites += 1

        # Only deal with Objects at level 7 and above.
        if 7 <= self.modelingLevel:
            new_objects = mtd[ 'obj' ]
            new_relations = mtd[ 'rel' ]

            for ignored in self.ignored_objects:
                if ignored in new_objects:
                    del( new_objects[ ignored ] )
                for k in new_relations.keys():
                    if ignored in k:
                        del( new_relations[ k ] )

            if 0 != len( new_objects ) or 0 != len( new_relations ):
                self._ingestObjects( ttls, sid, ts, new_objects, new_relations, agent.org_id, eid )
            #self._actor.log( 'finished storing objects %s: %s / %s' % ( routing[ 'event_type' ], len( new_objects ), len( new_relations )) )
        return ( True, )

    ###########################################################################
    #   LOGGING
    ###########################################################################
    def sanitizeJson( self, o ):
        if isinstance( o, dict ):
            for k, v in o.iteritems():
                o[ k ] = self.sanitizeJson( v )
        elif isinstance( o, ( list, tuple ) ):
            o = [ self.sanitizeJson( x ) for x in o ]
        elif isinstance( o, ( uuid.UUID, AgentId ) ):
            o = str( o )
        else:
            try:
                if isinstance( o, ( str, unicode ) ) and "\x00" in o: raise Exception()
                json.dumps( o )
            except:
                if self._use_b64:
                    o = base64.b64encode( o )
                else:
                    o = o.encode( 'hex' )

        return o

    def flattenRecord( self, o, newRoot = None, prefix = '' ):
        isEntry = newRoot is None
        if isEntry: newRoot = {}
        if type( o ) is dict:
            for k, v in o.iteritems():
                if -1 != k.find( '.' ):
                    newK = k[ k.find( '.' ) + 1 : ]
                else:
                    newK = k
                if '' != prefix:
                    newPrefix = '%s/%s' % ( prefix, newK )
                else:
                    newPrefix = newK
                val = self.flattenRecord( v, newRoot, newPrefix )
                if val is not None:
                    newRoot[ newPrefix ] = val
            return newRoot if isEntry else None
        elif type( o ) is list or type( o ) is tuple:
            i = 0
            for v in o:
                newPrefix = '%s_%d' % ( prefix, i )
                val = self.flattenRecord( v, newRoot, newPrefix )
                if val is not None:
                    newRoot[ newPrefix ] = v
                i += 1
            return newRoot if isEntry else None
        else:
            return o

    def logToDisk( self, routing, event, mtd ):
        if self._is_flat:
            event = self.flattenRecord( event )

        record = json.dumps( self.sanitizeJson( { 'routing' : routing, 
                                                  'event' : event } ) )
        
        self.file_logger.info( record )

        return ( True, )

    def reportDetectOrInv( self, msg ):
        record = msg.data

        if '' != self.loggingDir:
            if self._is_flat:
                record = self.flattenRecord( record )

            self.file_logger.info( json.dumps( self.sanitizeJson( record ) ) )
        if '' != self.s3Bucket:
            record = json.dumps( self.sanitizeJson( record ) )
            
            with self.s3Mutex:
                self.s3TmpHandle.write( record )
                self.s3TmpHandle.write( "\n" )
        if 0 < self.modelingLevel:
            self.asyncInsert( self.stmt_detect_report.bind( ( record[ 'detect_id' ].upper(), 
                                                              record[ 'source' ],
                                                              record[ 'cat' ],
                                                              ' / '.join( record[ 'msg_ids' ],
                                                              base64.b64encode( msgpack.packb( msg.data[ 'detect' ] ) ),
                                                              record[  'summary' ],
                                                              self.getOrgTtls( AgentId( record[ 'source' ] ).org_id ) ) ) ) )

        return ( True, )

    def logToS3( self, routing, event, mtd ):
        record = json.dumps( self.sanitizeJson( { 'routing' : routing, 
                                                  'event' : event } ) )
        
        with self.s3Mutex:
            self.s3TmpHandle.write( record )
            self.s3TmpHandle.write( "\n" )

        return ( True, )

    def s3Sync( self ):
        if self.s3TmpHandle is None:
            return

        with self.s3Mutex:
            toSend = self.s3TmpHandle
            self.s3TmpHandle = tempfile.NamedTemporaryFile( mode = 'w+b' )

        self._actor.delay( 0, self._s3SendBatch, toSend )

    def _s3SendBatch( self, h ):
        try:
            h.flush()
            h.seek( 0 )
            if 0 != os.path.getsize( h.name ):
                self.s3.upload_fileobj( h, self.s3Bucket, str( uuid.uuid4() ) )
        finally:
            h.close()
