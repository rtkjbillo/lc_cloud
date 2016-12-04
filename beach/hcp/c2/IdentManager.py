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
import traceback
import hashlib
import time
import uuid
CassDb = Actor.importLib( 'utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( 'utils/hcp_databases', 'CassPool' )

class IdentManager( Actor ):
    def init( self, parameters, resources ):
        self._db = CassDb( parameters[ 'db' ], 'hcp_analytics' )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )

        self.db.start()

        self.handle( 'authenticate', self.authenticate )
        self.handle( 'create_user', self.createUser )
        self.handle( 'create_org', self.createOrg )
        self.handle( 'add_user_to_org', self.addUserToOrg )
        self.handle( 'remove_user_from_org', self.removeUserFromOrg )
        
    def deinit( self ):
        pass

    def authenticate( self, msg ):
        req = msg.data

        emal = req[ 'email' ]
        password = req[ 'password' ]

        isAuthenticated = False
        info = self.db.getOne( 'SELECT uid, email, salt, salted_password FROM user_info WHERE email = %s', 
                               ( email, ) )

        if info is None:
            return ( True, { 'is_authenticated' : False } )

        uid, email, salt, salted_password = info

        if hashlib.sha256( '%s%s' % ( password, salt ) ).digest() != salted_password:
            return ( True, { 'is_authenticated' : False } )

        orgs = []
        info = self.db.execute( 'SELECT oid FROM org_membership WHERE uid = %s', ( uid, ) )
        if info is not None:
            for row in info:
                orgs.append( row[ 0 ] )

        return ( True, { 'is_authenticated' : True, 'uid' : uid, 'email' : email, 'orgs' : orgs } )

    def createUser( self, msg ):
        req = msg.data

        emal = req[ 'email' ]
        password = req[ 'password' ]
        uid = uuid.uuid4()
        salt = hashlib.sha256( str( uuid.uuid4() ) ).digest()
        salted_password = '%s%s' % ( password, salt )

        info = self.getOne( 'SELECT uid FROM user_info WHERE email = %s', ( email, ) )
        if info is not None:
            return ( True, { 'is_created' : False } )

        self.db.execute( 'INSERT INTO user_info ( email, uid, salt, salted_password ) VALUES ( %s, %s, %s, %s )', 
                         ( email, uid, salt, salted_password ) )

        return ( True, { 'is_created' : True, 'uid' : uid } )

    def createOrg( self, msg ):
        req = msg.data

        name = req[ 'name' ]
        oid = uuid.uuid4()

        self.db.execute( 'INSERT INTO org_info ( oid, name ) VALUES ( %s, %s )', ( oid, name ) )

        return ( True, { 'is_created' : True, 'oid' : oid } )

    def addUserToOrg( self, msg ):
        req = msg.data

        email = req[ 'email' ]
        oid = req[ 'oid' ]

        info = self.db.getOne( 'SELECT uid FROM user_info WHERE email = %s', ( email, ) )
        if info is None:
            return ( True, { 'is_added' : False } )
        uid = info[ 0 ]

        self.db.execute( 'INSERT INTO org_membership ( uid, oid ) VALUES ( %s, %s )', 
                         ( uid, oid ) )

        return ( True, { 'is_added' : True } )

    def removeUserFromOrg( self, msg ):
        req = msg.data

        email = req[ 'email' ]
        oid = req[ 'oid' ]

        info = self.db.getOne( 'SELECT uid FROM user_info WHERE email = %s', ( email, ) )
        if info is None:
            return ( True, { 'is_removed' : False } )
        uid = info[ 0 ]

        self.db.execute( 'DELETE org_membership WHERE uid = %s AND oid = %s )', 
                         ( uid, oid ) )

        return ( True, { 'is_removed' : True } )