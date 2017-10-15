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
from sets import Set
import hashlib
import base64
import uuid
import msgpack
import sys
import time
import re
import time_uuid
AgentId = Actor.importLib( './hcp_helpers', 'AgentId' )
chunks = Actor.importLib( './hcp_helpers', 'chunks' )
tsToTime = Actor.importLib( './hcp_helpers', 'tsToTime' )
timeToTs = Actor.importLib( './hcp_helpers', 'timeToTs' )
normalAtom = Actor.importLib( './hcp_helpers', 'normalAtom' )
try:
    CassDb = Actor.importLib( './hcp_databases', 'CassDb' )
except:
    print( "cassandra not installed, some functionality won't work" )

def ObjectNormalForm( objName, objType, isCaseSensitive = False ):
    if objType is not None and type( objType ) is not int:
        objType = ObjectTypes.forward[ objType ]
    caseSensitiveTypes = ( ObjectTypes.AUTORUNS,
                           ObjectTypes.CMD_LINE,
                           ObjectTypes.FILE_NAME,
                           ObjectTypes.FILE_PATH,
                           ObjectTypes.HANDLE_NAME,
                           ObjectTypes.MODULE_NAME,
                           ObjectTypes.PACKAGE,
                           ObjectTypes.PROCESS_NAME,
                           ObjectTypes.SERVICE_NAME )
    if ObjectTypes.FILE_HASH == objType:
        try:
            objName.decode( 'ascii' )
        except:
            objName = objName.encode( 'hex' )
    else:
        try:
            objName = unicode( objName )
            if not isCaseSensitive or objType not in caseSensitiveTypes:
                objName = objName.lower()
            objName = objName.encode( 'utf-8' )
        except:
            objName = base64.b64encode( objName )
        if ObjectTypes.FILE_PATH == objType:
            objName = NormalizePath( objName, isCaseSensitive = isCaseSensitive )
    return objName

def ObjectKey( objName, objType ):
    if type( objType ) is not int:
        objType = ObjectTypes.forward[ objType ]
    k = hashlib.sha256( '%s/%s' % ( objName, objType ) ).hexdigest()
    return k

def RelationNameFromId( pId, cId ):
    v = '%s/%s' % ( pId, cId )
    return v

def RelationName( pName, pType, cName, cType ):
    v = RelationNameFromId( ObjectKey( pName, pType ), ObjectKey( cName, cType ) )
    return v

def NormalizePath( path, isCaseSensitive = False ):
    for n in ( ( r'.:\\users\\.+?(\\.+)', r'%USERPROFILE%\1' ),
               ( r'.:\\documents and settings\\.+?(\\.+)', r'%USERPROFILE%\1' ),
               ( r'/Users/.+?(/.+)', r'$HOME\1' ),
               ( r'/home/.+?(/.+)', r'$HOME\1' ) ):
        path = re.sub( n[ 0 ], n[ 1 ], path, flags = ( 0 if isCaseSensitive else re.IGNORECASE ) )
    return path

class ObjectTypes (object):
    RELATION = 0
    FILE_PATH = 1
    FILE_NAME = 2
    PROCESS_NAME = 3
    MODULE_NAME = 4
    MODULE_SIZE = 5
    FILE_HASH = 6
    HANDLE_NAME = 7
    SERVICE_NAME = 8
    CMD_LINE = 9
    MEM_HEADER_HASH = 10
    PORT = 11
    THREADS = 12
    AUTORUNS = 13
    DOMAIN_NAME = 14
    PACKAGE = 15
    STRING = 16
    IP_ADDRESS = 17
    CERT_ISSUER = 18
    USER_NAME = 19

    tup = ( ( 'RELATION', 0 ),
            ( 'FILE_PATH', 1 ),
            ( 'FILE_NAME', 2 ),
            ( 'PROCESS_NAME', 3 ),
            ( 'MODULE_NAME', 4 ),
            ( 'MODULE_SIZE', 5 ),
            ( 'FILE_HASH', 6 ),
            ( 'HANDLE_NAME', 7 ),
            ( 'SERVICE_NAME', 8 ),
            ( 'CMD_LINE', 9 ),
            ( 'MEM_HEADER_HASH', 10 ),
            ( 'PORT', 11 ),
            ( 'THREADS', 12 ),
            ( 'AUTORUNS', 13 ),
            ( 'DOMAIN_NAME', 14 ),
            ( 'PACKAGE', 15 ),
            ( 'STRING', 16 ),
            ( 'IP_ADDRESS', 17 ),
            ( 'CERT_ISSUER', 18 ),
            ( 'USER_NAME', 19 ) )

    forward = { 'RELATION': 0,
                'FILE_PATH': 1,
                'FILE_NAME': 2,
                'PROCESS_NAME': 3,
                'MODULE_NAME': 4,
                'MODULE_SIZE': 5,
                'FILE_HASH': 6,
                'HANDLE_NAME': 7,
                'SERVICE_NAME': 8,
                'CMD_LINE': 9,
                'MEM_HEADER_HASH': 10,
                'PORT': 11,
                'THREADS': 12,
                'AUTORUNS': 13,
                'DOMAIN_NAME': 14,
                'PACKAGE': 15,
                'STRING': 16,
                'IP_ADDRESS': 17,
                'CERT_ISSUER' : 18,
                'USER_NAME' : 19 }

    rev = { 0 : 'RELATION',
            1 : 'FILE_PATH',
            2 : 'FILE_NAME',
            3 : 'PROCESS_NAME',
            4 : 'MODULE_NAME',
            5 : 'MODULE_SIZE',
            6 : 'FILE_HASH',
            7 : 'HANDLE_NAME',
            8 : 'SERVICE_NAME',
            9 : 'CMD_LINE',
            10 : 'MEM_HEADER_HASH',
            11 : 'PORT',
            12 : 'THREADS',
            13 : 'AUTORUNS',
            14 : 'DOMAIN_NAME',
            15 : 'PACKAGE',
            16 : 'STRING',
            17 : 'IP_ADDRESS',
            18 : 'CERT_ISSUER',
            19 : 'USER_NAME' }

def dbgprint( s ):
    sys.stderr.write( s + "\n" )
    sys.stderr.flush()

def _makeUuid( val ):
    if type( val ) is not uuid.UUID:
        try:
            val = uuid.UUID( val )
        except:
            val = uuid.UUID( bytes = val )
    return val

class HostObjects( object ):
    _db = None
    _isDbShared = False
    _idRe = re.compile( '^[a-zA-Z0-9]{64}$' )
    _queryChunks = 200

    @classmethod
    def setDatabase( cls, urlOrInstance ):
        if type( urlOrInstance ) in ( list, tuple, str, unicode ):
            cls._db = CassDb( urlOrInstance, 'hcp_analytics' )
        else:
            cls._db = urlOrInstance
            cls._isDbShared = True

    @classmethod
    def closeDatabase( cls ):
        if not cls._isDbShared:
            cls._db.shutdown()

    @classmethod
    def onHosts( cls, hosts, types = [], within = None ):
        if within is not None:
            within = int( time.time() ) - int( within )

        if type( hosts ) is not list and type( hosts ) is not tuple:
            hosts = ( hosts, )

        if type( types ) is not list and type( types ) is not tuple:
            types = ( types, )

        def thisGen():
            for host in hosts:
                if 0 == len( types ):
                    for row in cls._db.execute( 'SELECT id, last FROM loc WHERE sid = %s', ( AgentId( host ).sensor_id, ) ):
                        if within is None or int( time.mktime( row[ 1 ].timetuple() ) ) >= within:
                            yield row[ 0 ]
                else:
                    rows = []
                    for t in types:
                        for row in cls._db.execute( 'SELECT id, last FROM loc WHERE sid = %s AND otype = %s', ( AgentId( host ).sensor_id, cls._castType( t ) ) ):
                            if within is None or int( time.mktime( row[ 1 ].timetuple() ) ) >= within:
                                yield row[ 0 ]

        return cls( thisGen() )

    @classmethod
    def ofTypes( cls, types ):
        if type( types ) is not list and type( types ) is not tuple:
            types = ( types, )

        def thisGen():
            for t in types:
                # Because they are sharded in 256 shards and because the actual records' primary key includes an aid
                # there will be duplicates between shards and even within a single shard. So to provide a unified
                # view we need to summarize on a per-type basis.
                ids = Set()
                for d in range( 0, 256 ):
                    for row in cls._db.execute( 'SELECT id FROM loc_by_type WHERE d256 = %s AND otype = %s', ( d, cls._castType( t ) ) ):
                        ids.add( row[ 0 ] )
                for id in ids:
                    yield id

        return cls( thisGen() )

    @classmethod
    def matching( cls, ofType, withParents, withChildren ):
        if type( ofType ) is str or type( ofType ) is unicode:
            ofType = ObjectTypes.forward[ ofType ]

        def thisGen():
            ids = Set()
            for cid in withChildren:
                tmp = [ x[ 0 ] for x in cls._db.execute( 'SELECT pid FROM rel_man_child WHERE childKey = %s AND ptype = %s', ( cid, ofType ) ) ]
                if 0 == len( ids ):
                    ids = Set( tmp )
                else:
                    ids = ids.intersection( tmp )

            for pid in withParents:
                tmp = [ x[ 0 ] for x in cls._db.execute( 'SELECT cid FROM rel_man_parent WHERE parentKey = %s AND ctype = %s', ( pid, ofType ) ) ]
                if 0 == len( ids ):
                    ids = Set( tmp )
                else:
                    ids = ids.intersection( tmp )

            for id in ids:
                yield id

        return cls( thisGen() )

    @classmethod
    def named( cls, named ):

        def thisGen():
            for x in cls._db.execute( 'SELECT id FROM obj_man WHERE obj LIKE %s', ( ObjectNormalForm( named, None ), ) ):
                yield x[ 0 ]

        return cls( thisGen() )

    @classmethod
    def _castType( cls, t ):
        if type( t ) is str or type( t ) is unicode:
            return ObjectTypes.forward[ t ]
        else:
            return int( t )

    @classmethod
    def _castId( cls, id ):
        id = str( id )
        if cls._idRe.match( id ):
            return id.lower()
        else:
            return None

    def __init__( self, ids = [] ):
        if not hasattr( ids, '__iter__' ):
            ids = [ ids ]
        self._ids = ids

    def __iter__( self ):
        return self._ids.__iter__()

    def next( self ):
        return self._ids.next()

    def acl( self, oid = None ):
        if oid is None:
            return type(self)( self._ids )
        if type( oid ) not in ( list, tuple, Set ):
            oid = [ oid ]
        def thisGen():
            for ids in chunks( self._ids, self._queryChunks ):
                tmpIds = Set()
                for row in self._db.execute( 'SELECT id FROM obj_org WHERE id IN %s AND oid IN %s', ( ids, oid ) ):
                    if row[ 0 ] not in tmpIds:
                        tmpIds.add( row[ 0 ] )
                        yield row[ 0 ]


        return type(self)( thisGen() )

    def events( self, oid = None, after = None, before = None ):
        if oid is None:
            for row in self._db.execute( 'SELECT ts, sid, eid FROM obj_org WHERE id IN %s', ( self._ids, ) ):
                yield ( row[ 0 ], row[ 1 ], row[ 2 ] )
        else:
            if type( oid ) not in ( list, tuple, Set ):
                oid = [ oid ]
            for ids in chunks( self._ids, self._queryChunks ):
                timeFilt = ''
                params = [ ids, oid ]
                if after is not None:
                    timeFilt += ' AND ts >= %s'
                    params.append( int( after ) * 1000 )
                if before is not None:
                    timeFilt += ' AND ts <= %s'
                    params.append( int( before ) * 1000 )
                for row in self._db.execute( 'SELECT ts, sid, eid FROM obj_org WHERE id IN %s AND oid IN %s' + timeFilt, params ):
                    yield ( row[ 0 ], row[ 1 ], row[ 2 ] )

    def info( self ):
        for ids in chunks( self._ids, self._queryChunks ):
            try:
                for row in self._db.execute( 'SELECT id, obj, otype FROM obj_man WHERE id IN %s', ( ids, ) ):
                    yield ( row[ 0 ], row[ 1 ], row[ 2 ] )
            except:
                pass

    def locs( self, within = None, isLocalCloudOnly = False, oid = None ):
        if within is not None:
            within = int( time.time() ) - int( within )

        if oid is not None and type( oid ) not in ( list, tuple, Set ):
            oid = [ oid ]

        for ids in chunks( self._ids, self._queryChunks ):
            for rows in chunks( self._db.execute( 'SELECT id, sid, last FROM loc_by_id WHERE id IN %s', ( ids, ) ), self._queryChunks ):
                if oid is not None:
                    validSids = Set()
                    for tmpSid, tmpOid in self._db.execute( 'SELECT sid, oid FROM sensor_states WHERE sid IN %s', ( [ x[ 1 ] for x in rows ], ) ):
                        if tmpOid in oid:
                            validSids.add( tmpSid )
                else:
                    validSids = Set( x[ 1 ] for x in rows )
                for row in rows:
                    if row[ 1 ] not in validSids:
                        continue
                    ts = self._db.timeToMsTs( row[ 2 ] )
                    if within is None:
                        yield ( row[ 0 ], row[ 1 ], ts )
                    else:
                        if ts >= within:
                            yield ( row[ 0 ], row[ 1 ], ts )

    def children( self, types = None ):
        withType = ''
        if types is not None:
            withType = ' AND ctype = %d' % int( self._castType( types ) )

        def thisGen():
            for ids in chunks( self._ids, self._queryChunks ):
                for row in self._db.execute( 'SELECT cid FROM rel_man_parent WHERE parentkey IN %%s%s' % ( withType, ), ( ids, ) ):
                    yield row[ 0 ]

        return type(self)( thisGen() )

    def childrenRelations( self, types = None ):

        def thisGen():
            for id in self._ids:
                for child in type(self)( id ).children( types ):
                    yield ObjectKey( RelationNameFromId( id, child ), ObjectTypes.RELATION )

        return type(self)( thisGen() )

    def parents( self, types = None ):
        withType = ''
        if types is not None:
            withType = ' AND ptype = %d' % int( self._castType( types ) )

        def thisGen():
            for ids in chunks( self._ids, self._queryChunks ):
                for row in self._db.execute( 'SELECT pid FROM rel_man_child WHERE childkey IN %%s%s' % ( withType, ), ( ids, ) ):
                    yield row[ 0 ]

        return type(self)( thisGen() )

    def parentsRelations( self, types = None ):

        def thisGen():
            for id in self._ids:
                for parent in type(self)( id ).parents( types ):
                    yield ObjectKey( RelationNameFromId( parent, id ), ObjectTypes.RELATION )

        return type(self)( thisGen() )

    def lastSeen( self, forAgents = None ):
        if forAgents is not None and type( forAgents ) is not tuple and type( forAgents ) is not list:
            forAgents = ( forAgents, )
        forAgents = [ x.sensor_id for x in forAgents ]
        for ids in chunks( self._ids, self._queryChunks ):
            for row in self._db.execute( 'SELECT id, sid, last FROM loc_by_id WHERE id IN %s', ( ids, ) ):
                if forAgents is not None:
                    if row[ 1 ] not in forAgents:
                        continue
                yield ( row[ 0 ], row[ 1 ], row[ 2 ] )

class Host( object ):

    _be = None
    _db = None
    _isDbShared = False

    @classmethod
    def setDatabase( cls, beInstance, urlOrInstance ):
        cls._be = beInstance
        if type( urlOrInstance ) in ( list, tuple, str, unicode ):
            cls._db = CassDb( urlOrInstance, 'hcp_analytics' )
        else:
            cls._db = urlOrInstance
            cls._isDbShared = True

    @classmethod
    def closeDatabase( cls ):
        if not cls._isDbShared:
            cls._db.shutdown()

    @classmethod
    def getHostsMatching( cls, mask = None, hostname = None ):
        col = []
        agents = cls._be.hcp_getAgentStates( aid = mask, hostname = hostname )
        if agents.isSuccess and 'agents' in agents.data:
            col = [ Host( x ) for x in agents.data[ 'agents' ].keys() ]
        return col

    @classmethod
    def getSpecificEvent( self, id ):
        record = None

        id = _makeUuid( id )

        event = self._db.getOne( 'SELECT sid, event FROM events WHERE eventid = %s', ( id, ) )
        if event is not None:
            record = ( id, event[ 0 ], event[ 1 ] )

        return record

    @classmethod
    def getSpecificEvents( self, ids ):
        records = []

        events = self._db.execute( 'SELECT eventid, sid, event FROM events WHERE eventid IN %s', ( [ _makeUuid( x ) for x in ids ], ) )
        if events is not None:
            for event in events:
                records.append( ( event[ 0 ], event[ 1 ], event[ 2 ] ) )

        return records

    @classmethod
    def getHostsUsingIp( self, ip, after, before = None, inOrgs = tuple() ):
        if type( inOrgs ) not in ( list, tuple ):
            inOrgs = ( inOrgs, )
        inOrgs = map( _makeUuid, inOrgs )

        if before is None:
            before = int( time.time() + ( 60 * 60 * 1 ) ) * 1000
        if after is None:
            after = int( time.time() - ( 60 * 60 * 24 * 30 ) ) * 1000
        if 0 == len( inOrgs ):
            rows = self._db.execute( 'SELECT ts, sid FROM sensor_ip WHERE ip = %s AND ts >= %s AND ts <= %s', ( ip, after, before ) )
        else:
            rows = self._db.execute( 'SELECT ts, sid FROM sensor_ip WHERE ip = %s AND ts >= %s AND ts <= %s AND oid IN %s', ( ip, after, before, inOrgs ) )

        records = []
        for row in rows:
            records.append( ( row[ 0 ], row[ 1 ] ) )

        return records

    @classmethod
    def getHostsWithTag( self, tag, inOrgs = tuple() ):
        if type( inOrgs ) not in ( list, tuple ):
            inOrgs = ( inOrgs, )
        inOrgs = map( _makeUuid, inOrgs )

        rows = self._db.execute( 'SELECT sid FROM sensor_tags WHERE tag LIKE %s', ( tag, ) )

        records = []
        for row in rows:
            if 0 == len( inOrgs ) or Host( row[ 0 ] ).getFullAid().org_id in inOrgs:
                records.append( row[ 0 ] )

        return records

    def __init__( self, agentid ):
        if type( agentid  ) is not AgentId:
            agentid = AgentId( agentid )
        self.aid = agentid
        self.sid = agentid.sensor_id

    def __str__( self ):
        return str( self.sid )

    def isOnline( self ):
        isOnline = False
        last = self.lastSeen()
        if last is not None:
            if last >= time.time() - ( 60 * 1 ):
                isOnline = True
        
        return isOnline

    def getFullAid( self ):
        aid = None
        res = self._db.getOne( 'SELECT oid, iid, sid, plat, arch FROM sensor_states WHERE sid = %s', ( self.sid, ) )
        if res:
            aid = AgentId( ( res[ 0 ], res[ 1 ], res[ 2 ], res[ 3 ], res[ 4 ] ) )
        return aid

    def getLastIps( self ):
        ips = None
        res = self._db.getOne( 'SELECT ext_ip, int_ip FROM sensor_states WHERE sid = %s', ( self.sid, ) )
        if res:
            ips = ( res[ 0 ], res[ 1 ] )
        return ips

    def getHostName( self ):
        hostname = None

        info = self._be.hcp_getAgentStates( aid = self.sid )
        if info.isSuccess and 'agents' in info.data and 0 != len( info.data[ 'agents' ] ):
            info = info.data[ 'agents' ].values()[ 0 ]
            hostname = info[ 'last_hostname' ]

        return hostname

    def getStatusHistory( self, within = None ):
        statuses = []

        whereTs = ''
        filters = []
        filters.append( self.sid )
        if within is not None:
            ts = tsToTime( int( within ) )
            whereTs = ' AND ts >= minTimeuuid(%s)'
            filters.append( ts )

        results = self._db.execute( 'SELECT unixTimestampOf( ts ) FROM timeline WHERE sid = %%s AND eventtype = \'hbs.NOTIFICATION_STARTING_UP\'%s' % whereTs, filters )
        if results is not None:
            for result in results:
                statuses.append( ( result[ 0 ], True ) )

        results = self._db.execute( 'SELECT unixTimestampOf( ts ) FROM timeline WHERE sid = %%s AND eventtype = \'hbs.NOTIFICATION_SHUTTING_DOWN\'%s' % whereTs, filters )
        if results is not None:
            for result in results:
                statuses.append( ( result[ 0 ], False ) )

        return statuses

    def getEvents( self, before = None, after = None, limit = None, ofTypes = None, isIncludeContent = False ):
        events = []

        filters = []
        filterValues = []

        filters.append( 'sid = %s' )
        filterValues.append( self.sid )

        if before is not None and before != '':
            filters.append( 'ts <= %s' )
            filterValues.append( time_uuid.TimeUUID.with_timestamp( before, randomize = False, lowest_val = False ) )

        if after is not None and after != '':
            filters.append( 'ts >= %s' )
            filterValues.append( time_uuid.TimeUUID.with_timestamp( after, randomize = False, lowest_val = True ) )

        if ofTypes is not None:
            if type( ofTypes ) is not tuple and type( ofTypes ) is not list:
                ofTypes = ( ofTypes, )

        if limit is not None:
            limit = 'LIMIT %d' % int( limit )
        else:
            limit = ''

        def thisGen():
            if ofTypes is None:
                for row in self._db.execute( 'SELECT unixTimestampOf( ts ), eventtype, eventid FROM timeline WHERE %s%s' % ( ' AND '.join( filters ), limit ), filterValues ):
                    record = ( row[ 0 ], row[ 1 ], row[ 2 ] )
                    if isIncludeContent:
                        event = self._db.getOne( 'SELECT event FROM events WHERE eventid = %s', ( record[ 2 ], ) )
                        if event is not None:
                            record = ( record[ 0 ], record[ 1 ], record[ 2 ], event[ 0 ] )
                        else:
                            record = ( record[ 0 ], record[ 1 ], record[ 2 ], None )

                    yield record
            else:
                for t in ofTypes:
                    tmp_filters = [ 'eventtype = %s' ]
                    tmp_filters.extend( filters )
                    tmp_values = [ t ]
                    tmp_values.extend( filterValues )
                    for row in self._db.execute( 'SELECT unixTimestampOf( ts ), eventtype, eventid FROM timeline_by_type WHERE %s%s' % ( ' AND '.join( tmp_filters ), limit ), tmp_values ):
                        record = ( row[ 0 ], row[ 1 ], row[ 2 ] )
                        if isIncludeContent:
                            event = self._db.getOne( 'SELECT event FROM events WHERE eventid = %s', ( record[ 2 ], ) )
                            if event is not None:
                                record = ( record[ 0 ], record[ 1 ], record[ 2 ], event[ 0 ] )
                            else:
                                record = ( record[ 0 ], record[ 1 ], record[ 2 ], None )

                        yield record

        return thisGen()

    def lastEvents( self ):
        events = []

        for row in self._db.execute( 'SELECT type, id FROM last_events WHERE sid = %s', ( self.sid, ) ):
            events.append( { 'name' : row[ 0 ], 'id' : row[ 1 ] } )

        return events

    def getBandwidthUsage( self, after = None ):
        if after is None:
            after = time.time() - ( 60 * 60 * 24 * 1 )
        after = int( after ) * 1000
        values = []
        for row in self._db.execute( 'SELECT ts, b FROM sensor_transfer WHERE sid = %s AND ts >= %s', ( self.sid, after ) ):
            values.append( ( self._db.timeToMsTs( row[ 0 ] ), row[ 1 ] ) )
        return values

    def getTags( self ):
        tags = {}
        for row in self._db.execute( 'SELECT sid, tag, frm, added FROM sensor_tags WHERE sid = %s', ( self.sid, ) ):
            tags[ row[ 1 ] ] = ( row[ 0 ], row[ 1 ], row[ 2 ], row[ 3 ] )
        return tags

    def setTag( self, tag, by = '', ttl = ( 60 * 60 * 24 * 365 ) ):
        self._db.execute( 'INSERT INTO sensor_tags ( sid, tag, frm, added ) VALUES ( %s, %s, %s, dateOf(now()) ) USING TTL %s', ( self.sid, str( tag ).lower(), by, ttl ) )

    def unsetTag( self, tag ):
        self._db.execute( 'DELETE FROM sensor_tags WHERE sid = %s AND tag = %s', ( self.sid, str( tag ).lower() ) )

class FluxEvent( object ):
    @classmethod
    def decode( cls, data, withRouting = False, isFullDump = False ):
        event = None
        routing = None
        try:
            data = msgpack.unpackb( base64.b64decode( data ), use_list = True )
            if isFullDump:
                event = data
                cls._dataToUtf8( event )
            else:
                if 'event' in data:
                    event = data[ 'event' ]
                    cls._dataToUtf8( event )
                if 'routing' in data and withRouting:
                    routing = data[ 'routing' ]
                    cls._dataToUtf8( routing )
        except:
            event = None
            routing = None

        if withRouting and not isFullDump:
            return routing, event
        else:
            return event

    @classmethod
    def _dataToUtf8( cls, node ):
        newVal = None

        if type( node ) is dict:
            for k, n in node.iteritems():
                if 'base.HASH' == k or str( k ).endswith( '_HASH' ):
                    node[ k ] = n.encode( 'hex' )
                elif str( k ).endswith( '_ATOM' ) and type( n ) is str:
                    node[ k ] = normalAtom( n )
                else:
                    tmp = cls._dataToUtf8( n )
                    if tmp is not None:
                        node[ k ] = tmp
        elif type( node ) is list or type( node ) is tuple:
            for index, n in enumerate( node ):
                tmp = cls._dataToUtf8( n )
                if tmp is not None:
                    node[ index ] = tmp
        else:
            # This is a leaf
            if type( node ) is str:
                try:
                    newVal = node.decode( 'utf-8' )
                except:
                    newVal = None
        return newVal

class Reporting( object ):
    _db = None
    _isDbShared = False

    @classmethod
    def setDatabase( cls, urlOrInstance ):
        if type( urlOrInstance ) in ( list, tuple, str, unicode ):
            cls._db = CassDb( urlOrInstance, 'hcp_analytics' )
        else:
            cls._db = urlOrInstance
            cls._isDbShared = True

    @classmethod
    def closeDatabase( cls ):
        if not cls._isDbShared:
            cls._db.shutdown()

    @classmethod
    def getDetects( cls, oid = None, before = None, after = None, limit = None, id = None ):
        if id is None:
            filters = []
            filterValues = []

            if before is not None and before != '':
                filters.append( 'ts <= %s' )
                filterValues.append( time_uuid.TimeUUID.with_timestamp( before, randomize = False, lowest_val = False ) )

            if after is not None and after != '':
                filters.append( 'ts >= %s' )
                filterValues.append( time_uuid.TimeUUID.with_timestamp( after, randomize = False, lowest_val = True ) )

            if limit is not None:
                limit = 'LIMIT %d' % int( limit )
            else:
                limit = ''

            def thisGen():
                for row in cls._db.execute( 'SELECT did FROM detect_timeline WHERE oid = %s AND %s%s' % ( uuid.UUID( oid ), ' AND '.join( filters ), limit ), filterValues ):
                    for reprow in cls._db.execute( 'SELECT gen, did, source, dtype, events, detect, why FROM detects WHERE did = \'%s\'' % ( row[ 0 ],  ) ):
                        yield ( timeToTs( reprow[ 0 ] ) * 1000, reprow[ 1 ].upper(), reprow[ 2 ], reprow[ 3 ], reprow[ 4 ], reprow[ 5 ], reprow[ 6 ] )

            return thisGen()
        else:
            r = None
            id = id.upper()
            for row in cls._db.execute( 'SELECT gen, did, source, dtype, events, detect, why FROM detects WHERE did = \'%s\'' % ( id, ) ):
                r = ( timeToTs( row[ 0 ] ) * 1000, row[ 1 ].upper(), row[ 2 ], row[ 3 ], row[ 4 ], row[ 5 ], row[ 6 ] )
            return r

    @classmethod
    def getRelatedEvents( cls, id, isIncludeContent = True ):
        id = id.upper()
        for row in cls._db.execute( 'SELECT invid, unixTimestampOf( ts ), eid, etype FROM investigation_data WHERE invid = \'%s\'' % ( id, ) ):
            record = ( row[ 0 ].upper(), row[ 1 ], row[ 2 ], row[ 3 ] )
            if isIncludeContent:
                event = cls._db.getOne( 'SELECT event FROM events WHERE eventid = %s', ( record[ 2 ], ) )
                record = ( record[ 0 ], record[ 1 ], event[ 0 ], record[ 3 ], record[ 2 ] )
            yield record

    @classmethod
    def getInvestigations( cls, id, hunter = None ):
        id = id.upper()
        investigations = {}
        for row in cls._db.execute( 'SELECT hunter, gen, closed, nature, conclusion, why FROM investigation WHERE invid = \'%s\'' % ( id, ) ):
            investigations[ row[ 0 ] ] = { 'hunter' : row[ 0 ],
                                           'generated' : row[ 1 ], 
                                           'closed' : row[ 2 ], 
                                           'nature' : row[ 3 ], 
                                           'conclusion' : row[ 4 ], 
                                           'why' : row[ 5 ],
                                           'data' : [],
                                           'tasks' : [] }
        for row in cls._db.execute( 'SELECT hunter, unixTimestampOf( gen ), why, data FROM inv_data WHERE invid = \'%s\'' % ( id, ) ):
            investigations[ row[ 0 ] ][ 'data' ].append( { 'hunter' : row[ 0 ],
                                                           'generated' : row[ 1 ], 
                                                           'why' : row[ 2 ], 
                                                           'data' : row[ 3 ] } )
        for row in cls._db.execute( 'SELECT hunter, unixTimestampOf( gen ), why, dest, data, sent FROM inv_task WHERE invid = \'%s\'' % ( id, ) ):
            investigations[ row[ 0 ] ][ 'tasks' ].append( { 'hunter' : row[ 0 ],
                                                            'generated' : row[ 1 ], 
                                                            'why' : row[ 2 ], 
                                                            'dest' : row[ 3 ],
                                                            'data' : row[ 4 ],
                                                            'sent' : ( 0 != row[ 5 ] ) } )
        return investigations


class KeyValueStore( object ):
    _db = None
    _isDbShared = False
    _keySelect = None
    _keySet = None
    _keyTouch = None

    @classmethod
    def setDatabase( cls, urlOrInstance ):
        if type( urlOrInstance ) in ( list, tuple, str, unicode ):
            cls._db = CassDb( urlOrInstance, 'hcp_analytics' )
        else:
            cls._db = urlOrInstance
            cls._isDbShared = True
        cls._keySet = cls._db.prepare( 'INSERT INTO keyvalue ( k, c, v, cts ) VALUES ( ?, ?, ?, dateOf(now()) ) USING TTL ?' )
        cls._keySelect = cls._db.prepare( 'SELECT v, cts FROM keyvalue WHERE k = ? AND c = ?' )

    @classmethod
    def closeDatabase( cls ):
        if not cls._isDbShared:
            cls._db.shutdown()

    @classmethod
    def setKey( cls, cat, k, v, ttl = ( 60 * 60 * 24 * 30 ) ):
        return cls._db.execute( cls._keySet.bind( ( k, cat, v, ttl ) ) )

    @classmethod
    def getKey( cls, cat, k ):
        ret = None
        res = cls._db.getOne( cls._keySelect.bind( ( k, cat ) ) )
        if res:
            ret = ( res[ 0 ], res[ 1 ] )
        return ret

class Atoms ( object ):
    _db = None
    _isDbShared = False
    _atomSelect = None
    _queryChunks = 200

    @classmethod
    def setDatabase( cls, urlOrInstance ):
        if type( urlOrInstance ) in ( list, tuple, str, unicode ):
            cls._db = CassDb( urlOrInstance, 'hcp_analytics' )
        else:
            cls._db = urlOrInstance
            cls._isDbShared = True

    @classmethod
    def closeDatabase( cls ):
        if not cls._isDbShared:
            cls._db.shutdown()

    def __init__( self, ids ):
        self._ids = []
        if not hasattr( ids, '__iter__' ):
            self._ids = [ ( normalAtom( ids ), None ) ]
        else:
            self._ids = [ x if 2 == len( x ) else ( normalAtom( x ), None ) for x in ids ]

    def __iter__( self ):
        return self._ids.__iter__()

    def next( self ):
        return self._ids.next()

    def children( self ):
        def thisGen():
            for ids in chunks( self._ids, self._queryChunks ):
                for row in self._db.execute( 'SELECT child, eid FROM atoms_children WHERE atomid IN %s', ( [ _makeUuid( x[ 0 ] ) for x in ids ], ) ):
                    yield ( normalAtom( row[ 0 ] ), row[ 1 ] )
        return type(self)( thisGen() )

    def events( self, withRouting = False ):
        for ids in chunks( self._ids, self._queryChunks ):
            for event in Host.getSpecificEvents( x[ 1 ] for x in ids ):
                yield FluxEvent.decode( event[ 2 ], withRouting = withRouting )

    def fillEventIds( self ):
        def thisGen():
            for ids in chunks( self._ids, self._queryChunks ):
                for row in self._db.execute( 'SELECT atomid, eid FROM atoms_lookup WHERE atomid IN %s', ( [ _makeUuid( x[ 0 ] ) for x in ids ], ) ):
                    yield ( normalAtom( row[ 0 ] ), row[ 1 ] )
        return type(self)( thisGen() )

