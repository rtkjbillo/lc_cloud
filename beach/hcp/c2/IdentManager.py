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
import time
import uuid
import base64
import random
import string
import struct
import hmac
CassDb = Actor.importLib( 'utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( 'utils/hcp_databases', 'CassPool' )

class IdentManager( Actor ):
    def init( self, parameters, resources ):
        self._db = CassDb( parameters[ 'db' ], 'hcp_analytics', consistencyOne = True )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )

        self.db.start()

        self.audit = self.getActorHandle( resources[ 'auditing' ] )
        self.page = self.getActorHandle( resources[ 'paging' ] )
        self.deployment = self.getActorHandle( resources[ 'deployment' ] )
        self.enrollments = self.getActorHandle( resources[ 'enrollments' ] )

        resp = self.deployment.request( 'get_global_config', {} )
        if resp.isSuccess:
            self.admin_oid = uuid.UUID( resp.data[ 'global/admin_oid' ] )
        else:
            raise Exception( 'could not get admin oid' )

        self.genDefaultsIfNotPresent()

        self.handle( 'authenticate', self.authenticate )
        self.handle( 'create_user', self.createUser )
        self.handle( 'delete_user', self.deleteUser )
        self.handle( 'change_password', self.changePassword )
        self.handle( 'create_org', self.createOrg )
        self.handle( 'remove_org', self.removeOrg )
        self.handle( 'add_user_to_org', self.addUserToOrg )
        self.handle( 'remove_user_from_org', self.removeUserFromOrg )
        self.handle( 'get_org_info', self.getOrgInfo )
        self.handle( 'get_org_members', self.getOrgMembers )
        self.handle( 'get_user_membership', self.getUserMembership )
        self.handle( 'get_user_info', self.getUserInfo )
        self.handle( 'confirm_email', self.confirmEmail )
        
    def deinit( self ):
        pass

    def genDefaultsIfNotPresent( self ):
        info = self.db.getOne( 'SELECT COUNT(*) FROM user_info' )
        if 0 == info[ 0 ]:
            self.log( 'no existing users, generating default creds (user: admin@limacharlie, pass: letmein)' )

            class _dummyRequest ( object ):
                def __init__( self, data ):
                    self.data = data

            defaultAdminEmail = 'admin@limacharlie'

            self.createUser( _dummyRequest( { 'email' : defaultAdminEmail, 'password' : 'letmein', 'by' : 'limacharlie', 'no_confirm' : True } ) )
            self.createOrg( _dummyRequest( { 'name' : 'ADMIN_ORG', 'by' : 'limacharlie', 'existing_oid' : self.admin_oid } ) )
            self.addUserToOrg( _dummyRequest( { 'email' : defaultAdminEmail, 'oid' : self.admin_oid, 'by' : 'limacharlie' } ) )

    def asUuidList( self, elem ):
        if type( elem ) not in ( list, tuple ):
            elem = [ elem ]
        return map( uuid.UUID, elem )

    def authenticate( self, msg ):
        req = msg.data

        email = req[ 'email' ].lower()
        password = req[ 'password' ]
        totp = req[ 'totp' ]

        if 0 == len( email ) or 0 == len( password ):
            return ( True, { 'is_authenticated' : False } )

        isAuthenticated = False
        info = self.db.getOne( 'SELECT uid, email, salt, salted_password, is_deleted, must_change_password, confirmation_token, totp_secret FROM user_info WHERE email = %s', 
                               ( email, ) )

        if info is None or info[ 4 ] is True:
            return ( True, { 'is_authenticated' : False } )

        uid, email, salt, salted_password, is_deleted, must_change_password, confirmationToken, totp_secret = info

        if confirmationToken is not None and confirmationToken != '':
            return ( True, { 'is_authenticated' : False, 'needs_confirmation' : True } )

        if hashlib.sha256( '%s%s' % ( password, salt ) ).hexdigest() != salted_password:
            return ( True, { 'is_authenticated' : False } )

        if not must_change_password:
            otp = TwoFactorAuth( username = email, secret = totp_secret )
            if not otp.isAuthentic( totp ):
                return ( True, { 'is_authenticated' : False } )

        orgs = []
        info = self.db.execute( 'SELECT oid FROM org_membership WHERE uid = %s', ( uid, ) )
        if info is not None:
            for row in info:
                orgs.append( row[ 0 ] )

        for oid in orgs:
            self.audit.shoot( 'record', { 'oid' : oid, 'etype' : 'login', 'msg' : 'User %s logged in.' % email } )

        loginData = { 'is_authenticated' : True, 'uid' : uid, 'email' : email, 'orgs' : orgs, 'must_change_password' : must_change_password }
        if must_change_password:
            domain = 'LimaCharlie'
            resp = self.deployment.request( 'get_global_config', {} )
            if resp.isSuccess:
                domain = resp.data[ 'global/uidomain' ]
            totp = TwoFactorAuth( username = email, secret = totp_secret )
            loginData[ 'otp' ] = totp.getSecret( asOtp = True, domain = domain )
        return ( True, loginData )

    def createUser( self, msg ):
        req = msg.data

        email = req[ 'email' ].lower()
        password = req[ 'password' ]
        byUser = req[ 'by' ]
        isNoConfirm = req.get( 'no_confirm', False )
        uid = uuid.uuid4()
        salt = hashlib.sha256( str( uuid.uuid4() ) ).hexdigest()
        salted_password = hashlib.sha256( '%s%s' % ( password, salt ) ).hexdigest()
        confirmationToken = str( uuid.uuid4() )

        otp = TwoFactorAuth( username = email )
        
        info = self.db.getOne( 'SELECT uid, is_deleted FROM user_info WHERE email = %s', ( email, ) )
        if info is not None and info[ 1 ] is not True:
            return ( True, { 'is_created' : False } )

        self.db.execute( 'INSERT INTO user_info ( email, uid, salt, salted_password, totp_secret, confirmation_token, is_deleted, must_change_password ) VALUES ( %s, %s, %s, %s, %s, %s, false, true )', 
                         ( email, uid, salt, salted_password, otp.getSecret( asOtp = False ), '' if isNoConfirm else confirmationToken ) )

        self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'user_create', 'msg' : 'User %s created by %s.' % ( email, byUser ) } )

        return ( True, { 'is_created' : True, 
                         'uid' : uid, 
                         'confirmation_token' : confirmationToken } )

    def deleteUser( self, msg ):
        req = msg.data

        email = req[ 'email' ].lower()
        byUser = req[ 'by' ]

        info = self.db.getOne( 'SELECT uid FROM user_info WHERE email = %s', ( email, ) )
        if info is None:
            return ( True, { 'is_deleted' : False } )

        uid = info[ 0 ]

        self.db.execute( 'UPDATE user_info SET is_deleted = true WHERE email = %s', 
                         ( email, ) )

        self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'user_deleted', 'msg' : 'User %s deleted by %s.' % ( email, byUser ) } )

        return ( True, { 'is_deleted' : True, 'uid' : uid } )

    def changePassword( self, msg ):
        req = msg.data

        email = req[ 'email' ].lower()
        password = req[ 'password' ]
        byUser = req[ 'by' ]
        totp = req.get( 'totp', None )
        salt = hashlib.sha256( str( uuid.uuid4() ) ).hexdigest()
        salted_password = hashlib.sha256( '%s%s' % ( password, salt ) ).hexdigest()

        info = self.db.getOne( 'SELECT uid, totp_secret FROM user_info WHERE email = %s', ( email, ) )
        if info is None:
            return ( True, { 'is_changed' : False } )

        uid = info[ 0 ]
        totp_secret = info[ 1 ]

        if totp is not None:
            otp = TwoFactorAuth( username = email, secret = totp_secret )
            if not otp.isAuthentic( totp ):
                return ( True, { 'is_changed' : False } )

        self.db.execute( 'UPDATE user_info SET salt = %s, salted_password = %s, must_change_password = false WHERE email = %s', 
                         ( salt, salted_password, email ) )

        self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'password_change', 'msg' : 'User %s password changed by %s.' % ( email, byUser ) } )

        return ( True, { 'is_changed' : True, 'uid' : uid } )

    def createOrg( self, msg ):
        req = msg.data

        name = req[ 'name' ]
        byUser = req[ 'by' ]
        ttl_events = req.get( 'ttl_events', 86400 * 7 )
        ttl_long_obj = req.get( 'ttl_long_obj', 86400 * 31 )
        ttl_short_obj = req.get( 'ttl_short_obj', 86400 * 7 )
        ttl_atoms = req.get( 'ttl_atoms', 86400 * 7 )
        ttl_detections = req.get( 'ttl_detections', 86400 * 7 )
        oid = uuid.UUID( str( req.get( 'existing_oid', uuid.uuid4() ) ) )

        self.db.execute( 'INSERT INTO org_info ( oid, name, ttl_events, ttl_long_obj, ttl_short_obj, ttl_atoms, ttl_detections ) VALUES ( %s, %s, %s, %s, %s, %s, %s )', 
                         ( oid, name, ttl_events, ttl_long_obj, ttl_short_obj, ttl_atoms, ttl_detections ) )

        self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'org_create', 'msg' : 'Org %s ( %s ) created by %s.' % ( name, oid, byUser ) } )
        self.enrollments.broadcast( 'reload' )

        return ( True, { 'is_created' : True, 'oid' : oid } )

    def removeOrg( self, msg ):
        req = msg.data

        byUser = req[ 'by' ]
        oid = uuid.UUID( req[ 'oid' ] )

        self.db.execute( 'DELETE FROM org_info WHERE oid = %s', ( oid, ) )
        self.db.execute( 'DELETE FROM hcp_installers WHERE oid = %s', ( oid, ) )
        self.db.execute( 'DELETE FROM org_membership WHERE oid = %s', ( oid, ) )
        self.db.execute( 'DELETE FROM org_sensors WHERE oid = %s', ( oid, ) )

        self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'org_remove', 'msg' : 'Org %s removed by %s.' % ( oid, byUser ) } )

        return ( True, { 'is_created' : True, 'oid' : oid } )

    def addUserToOrg( self, msg ):
        req = msg.data

        email = req[ 'email' ].lower()
        oid = uuid.UUID( str( req[ 'oid' ] ) )
        byUser = req[ 'by' ]

        info = self.db.getOne( 'SELECT uid FROM user_info WHERE email = %s', ( email, ) )
        if info is None:
            return ( True, { 'is_added' : False } )
        uid = info[ 0 ]

        self.db.execute( 'INSERT INTO org_membership ( uid, oid ) VALUES ( %s, %s )', 
                         ( uid, oid ) )

        self.audit.shoot( 'record', { 'oid' : oid, 'etype' : 'org_user', 'msg' : 'User %s added to org by %s.' % ( email, byUser ) } )

        allUsers = self.db.execute( 'SELECT uid FROM org_membership WHERE oid = %s', ( oid, ) )
        if allUsers is not None:
            for row in allUsers:
                userInfo = self.db.getOne( 'SELECT email FROM user_info WHERE uid = %s', ( row[ 0 ], ) )
                self.page.shoot( 'page', 
                                 { 'to' : userInfo[ 0 ], 
                                   'msg' : 'The user %s has been added to the organization %s by %s.' % ( email, oid, byUser ), 
                                   'subject' : 'User added to org' } )

        return ( True, { 'is_added' : True } )

    def removeUserFromOrg( self, msg ):
        req = msg.data

        email = req[ 'email' ].lower()
        oid = uuid.UUID( req[ 'oid' ] )
        byUser = req[ 'by' ]

        info = self.db.getOne( 'SELECT uid FROM user_info WHERE email = %s', ( email, ) )
        if info is None:
            return ( True, { 'is_removed' : False } )
        uid = info[ 0 ]

        res = self.db.getOne( 'SELECT uid FROM org_membership WHERE uid = %s AND oid = %s', 
                              ( uid, oid ) )
        if res is None:
            return ( True, { 'is_removed' : False } )

        self.db.execute( 'DELETE FROM org_membership WHERE uid = %s AND oid = %s', 
                         ( uid, oid ) )

        self.audit.shoot( 'record', { 'oid' : oid, 'etype' : 'org_user', 'msg' : 'User %s removed from org by %s.' % ( email, byUser ) } )

        allUsers = self.db.execute( 'SELECT uid FROM org_membership WHERE oid = %s', ( oid, ) )
        if allUsers is not None:
            for row in allUsers:
                userInfo = self.db.getOne( 'SELECT email FROM user_info WHERE uid = %s', ( row[ 0 ], ) )
                self.page.shoot( 'page', 
                                 { 'to' : userInfo[ 0 ], 
                                   'msg' : 'The user %s has been removed from organization %s by %s.' % ( email, oid, byUser ), 
                                   'subject' : 'User added to org' } )

        return ( True, { 'is_removed' : True } )

    def getOrgInfo( self, msg ):
        req = msg.data

        isAll = req.get( 'include_all', False )

        if not isAll:
            oid = self.asUuidList( req[ 'oid' ] )
        else:
            oid = []

        info = self.db.execute( 'SELECT name, oid, ttl_events, ttl_long_obj, ttl_short_obj, ttl_atoms, ttl_detections FROM org_info' )
        if info is None:
            return ( False, 'error getting org info' )

        orgs = []
        for row in info:
            if row[ 1 ] in oid or isAll:
                orgs.append( ( row[ 0 ], row[ 1 ], { 'events' : row[ 2 ], 
                                                     'long_obj' : row[ 3 ],
                                                     'short_obj' : row[ 4 ],
                                                     'atoms' : row[ 5 ],
                                                     'detections' : row[ 6 ] } ) )

        return ( True, { 'orgs' : orgs } )

    def getOrgMembers( self, msg ):
        req = msg.data

        oids = self.asUuidList( req[ 'oid' ] )
        
        membership = {}
        for oid in oids:
            info = self.db.execute( 'SELECT oid, uid FROM org_membership WHERE oid = %s', ( oid, ) )
            if info is None:
                return ( False, 'error getting org membership' )

            for row in info:
                membership.setdefault( row[ 0 ], {} ).setdefault( row[ 1 ], None )

        for oid, org in membership.iteritems():
            for uid in org.keys():
                info = self.db.getOne( 'SELECT email, is_deleted FROM user_info WHERE uid = %s', ( uid, ) )
                if info is None:
                    return ( False, 'error getting user info' )
                if info[ 1 ] is False:
                    org[ uid ] = info[ 0 ]
                else:
                    del( org[ uid ] )

        return ( True, { 'orgs' : membership } )

    def getUserMembership( self, msg ):
        req = msg.data

        uid = uuid.UUID( req[ 'uid' ] )

        orgs = []
        info = self.db.execute( 'SELECT oid FROM org_membership WHERE uid = %s', ( uid, ) )
        if info is not None:
            for row in info:
                orgs.append( row[ 0 ] )

        return ( True, { 'uid' : uid, 'orgs' : orgs } )

    def getUserInfo( self, msg ):
        req = msg.data

        uids = req.get( 'uid', None )
        if uids is not None:
            uids = self.asUuidList( uids )

        isAllIncluded = req.get( 'include_all', False )
        isIncludeDeleted = req.get( 'include_deleted', False )

        res = {}

        if isAllIncluded:
            for row in self.db.execute( 'SELECT uid, email, is_deleted FROM user_info' ):
                if isIncludeDeleted or not row[ 2 ]:
                    res[ row[ 0 ] ] = row[ 1 ]
        else:
            for uid in uids:
                info = self.db.getOne( 'SELECT uid, email, is_deleted FROM user_info WHERE uid = %s', ( uid, ) )
                if not info:
                    return ( False, 'error getting user info' )
                if isIncludeDeleted or not info[ 2 ]:
                    res[ info[ 0 ] ] = info[ 1 ]
                else:
                    return ( False, 'error getting user info (deleted)' )
        return ( True, res )

    def confirmEmail( self, msg ):
        req = msg.data

        token = msg.data[ 'token' ]
        email = msg.data[ 'email' ].lower()

        info = self.db.getOne( 'SELECT uid, confirmation_token, must_change_password FROM user_info WHERE email = %s', ( email, ) )

        if info is None or not info[ 2 ]:
            return ( True, { 'confirmed' : False } )
        elif info[ 1 ] != token and '' != info[ 1 ]:
            return ( True, { 'confirmed' : True, 'uid' : info[ 0 ] } )
        else:
            self.db.execute( 'UPDATE user_info SET confirmation_token = \'\' WHERE email = %s', ( email, ) )
            return ( True, { 'confirmed' : True, 'uid' : info[ 0 ] } )

class TwoFactorAuth( object ):
    def __init__( self, username = None, secret = None ):
        self._isNew = False
        if secret is None:
            secret = base64.b32encode( ''.join( random.choice( string.ascii_letters + string.digits ) for _ in range( 16 ) ) )[ 0 : 16 ]
            self._isNew = True
        self._secret = secret
        self._username = username
        
    def _get_hotp_token( self, intervals_no ):
        key = base64.b32decode( self._secret, True )
        msg = struct.pack( ">Q", intervals_no )
        h = hmac.new( key, msg, hashlib.sha1 ).digest()
        o = ord( h[ 19 ] ) & 15
        h = ( struct.unpack( ">I", h[ o : o + 4 ])[ 0 ] & 0x7fffffff ) % 1000000
        return h
    
    def _get_totp_token( self ):
        i = int( time.time() ) / 30
        return ( self._get_hotp_token( intervals_no = i - 1 ),
                 self._get_hotp_token( intervals_no = i ),
                 self._get_hotp_token( intervals_no = i + 1 ) )

    def isAuthentic( self, providedValue ):
        if self._isNew:
            return False
        tokens = self._get_totp_token()
        return ( providedValue == tokens[ 0 ] or
                 providedValue == tokens[ 1 ] or
                 providedValue == tokens[ 2 ] )
    
    def getSecret( self, asOtp = False, domain = None ):
        if asOtp is False:
            return self._secret
        else:
            return 'otpauth://totp/%s@%s?secret=%s' % ( self._username, domain, self._secret )
