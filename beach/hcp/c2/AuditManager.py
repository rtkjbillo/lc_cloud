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
import uuid
CassDb = Actor.importLib( 'utils/hcp_databases', 'CassDb' )

class AuditManager( Actor ):
    def init( self, parameters, resources ):
        self.db = CassDb( parameters[ 'db' ], 'hcp_analytics' )

        self.handle( 'record', self.record )
        self.handle( 'get_log', self.getLog )

    def deinit( self ):
        self.db.shutdown()

    def asUuidList( self, elem ):
        if type( elem ) not in ( list, tuple ):
            elem = [ elem ]
        return map( uuid.UUID, elem )

    def record( self, msg ):
        req = msg.data

        oid = uuid.UUID( req[ 'oid' ] )
        etype = req[ 'etype' ]
        message = req[ 'msg' ]

        self.db.execute( 'INSERT INTO audit ( oid, ts, etype, msg ) VALUES ( %s, now(), %s, %s )', 
                         ( oid, etype, message ) )

        return ( True, )

    def getLog( self, msg ):
        req = msg.data

        oids = self.asUuidList( req[ 'oid' ] )
        limit = req.get( 'limit', 100 )

        logs = {}
        for oid in oids:
            logs[ oid ] = []
            res = self.db.execute( 'SELECT unixTimestampOf( ts ), etype, msg FROM audit WHERE oid = %s ORDER BY ts DESC LIMIT %s', 
                                   ( oid, limit ) )
            for row in res:
                logs[ oid ].append( ( row[ 0 ], row[ 1 ], row[ 2 ] ) )

        return ( True, { 'logs' : logs } )