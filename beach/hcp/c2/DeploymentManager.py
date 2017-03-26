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
import M2Crypto
import tempfile
import os
import hashlib
import base64
import time
import uuid
import msgpack
import random
CassDb = Actor.importLib( 'utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( 'utils/hcp_databases', 'CassPool' )

class DeploymentManager( Actor ):
    def init( self, parameters, resources ):
        self.admin_oid = parameters.get( 'admin_oid', None )
        if self.admin_oid is None: raise Exception( 'Admin OID must be specified.' )

        self._db = CassDb( parameters[ 'db' ], 'hcp_analytics', consistencyOne = True )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )

        self.db.start()

        self.audit = self.getActorHandle( resources[ 'auditing' ] )
        self.page = self.getActorHandle( resources[ 'paging' ] )

        self.genDefaultsIfNotPresent()

        self.handle( 'get_global_config', self.get_global_config )
        self.handle( 'set_config', self.set_config )
        self.handle( 'deploy_org', self.deploy_org )
        self.handle( 'get_c2_cert', self.get_c2_cert )
        
    def deinit( self ):
        pass

    def generateKey( self ):
        key = {
            'pub' : None,
            'pubDer' : None,
            'pri' : None,
            'priDer' : None,
        }

        r = M2Crypto.RSA.gen_key( 2048, 65537 )

        tmpHandle, tmpPath = tempfile.mkstemp()
        r.save_pub_key( tmpPath )
        with open( tmpPath, 'rb' ) as f:
            key[ 'pub' ] = f.read()
        os.close( tmpHandle )
        os.unlink( tmpPath )

        tmpHandle, tmpPath = tempfile.mkstemp()
        r.save_key( tmpPath, None )
        with open( tmpPath, 'rb' ) as f:
            key[ 'pri' ] = f.read()
        os.system( 'openssl rsa -in %s -out %s.pub.der -outform DER -pubout' % ( tmpPath, tmpPath ) )
        with open( '%s.pub.der' % tmpPath, 'rb' ) as f:
            key[ 'pubDer' ] = f.read()
        os.close( tmpHandle )
        os.unlink( tmpPath )
        os.unlink( '%s.pub.der' % tmpPath )

        tmpHandle, tmpPath = tempfile.mkstemp()
        r.save_key_der( tmpPath )
        with open( tmpPath, 'rb' ) as f:
            key[ 'priDer' ] = f.read()
        os.close( tmpHandle )
        os.unlink( tmpPath )

        return key

    def generateCert( self ):
        cert = {
            'key' : None,
            'cert' : None,
        }
        
        tmpHandle, tmpPath = tempfile.mkstemp()
        os.system( 'openssl req -x509 -newkey rsa:4096 -keyout %s_key.pem -out %s_cert.pem -nodes -sha256 -subj "/C=US/ST=CA/L=Mountain View/O=refractionPOINT/CN=rp_c2_dev"' % ( tmpPath, tmpPath ) )
        
        with open( '%s_key.pem' % tmpPath, 'rb' ) as f:
            cert[ 'key' ] = f.read()
        os.close( tmpHandle )
        os.unlink( '%s_key.pem' % tmpPath )

        with open( '%s_cert.pem' % tmpPath, 'rb' ) as f:
            cert[ 'cert' ] = f.read()
        os.unlink( '%s_cert.pem' % tmpPath )

        return cert

    def packKey( self, key ):
        return base64.b64encode( msgpack.packb( key ) )

    def unpackKey( self, key ):
        return msgpack.unpackb( base64.b64decode( key ) )

    def genDefaultsIfNotPresent( self ):
        isNeedDefaults = False

        # Root Key is the canary for needing to generate defaults
        info = self.db.getOne( 'SELECT conf, value FROM configs WHERE conf = %s', ( 'key/root', ) )
        if info is None or '' == info[ 1 ]:
            isNeedDefaults = True

        if isNeedDefaults:
            self.log( 'missing defaults, generating them' )
            rootKey = self.packKey( self.generateKey() )
            c2Cert = self.packKey( self.generateCert() )
            secret = str( uuid.uuid4() )
            primaryDomain = 'rp_c2_dev'
            primaryPort = '443'
            secondaryDomain = '127.0.0.1'
            secondaryPort = '443'
            self.log( 'loading root ket' )
            self.db.execute( 'INSERT INTO configs ( conf, value ) VALUES ( %s, %s )', ( 'key/root', rootKey ) )
            self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'conf_change', 'msg' : 'New root key pair generated.' } )

            self.log( 'loading c2 cert' )
            self.db.execute( 'INSERT INTO configs ( conf, value ) VALUES ( %s, %s )', ( 'key/c2', c2Cert ) )
            self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'conf_change', 'msg' : 'New c2 cert generated.' } )
            
            self.log( 'loading enrollment secret' )
            self.db.execute( 'INSERT INTO configs ( conf, value ) VALUES ( %s, %s )', ( 'global/enrollmentsecret', secret ) )
            self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'conf_change', 'msg' : 'New enrollment secret generated.' } )

            self.log( 'loading primary domain and port' )
            self.db.execute( 'INSERT INTO configs ( conf, value ) VALUES ( %s, %s )', ( 'global/primary', primaryDomain ) )
            self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'conf_change', 'msg' : 'Setting primary domain: %s.' % primaryDomain } )
            self.db.execute( 'INSERT INTO configs ( conf, value ) VALUES ( %s, %s )', ( 'global/primary_port', primaryPort ) )
            self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'conf_change', 'msg' : 'Setting primary port: %s.' % primaryPort } )

            self.log( 'loading secondary domain and port' )
            self.db.execute( 'INSERT INTO configs ( conf, value ) VALUES ( %s, %s )', ( 'global/secondary', secondaryDomain ) )
            self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'conf_change', 'msg' : 'Setting secondary domain: %s.' % secondaryDomain } )
            self.db.execute( 'INSERT INTO configs ( conf, value ) VALUES ( %s, %s )', ( 'global/secondary_port', secondaryPort ) )
            self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'conf_change', 'msg' : 'Setting secondary port: %s.' % secondaryPort } )

    def get_global_config( self, msg ):
        self.log( 'get_global_config' )
        req = msg.data

        globalConf = {
            'global/primary' : '',
            'global/secondary' : '',
            'global/primary_port' : '',
            'global/secondary_port' : '',
            'global/enrollmentsecret' : '',
            'global/sensorpackage' : '',
            'global/paging_user' : '',
            'global/paging_from' : '',
            'global/paging_password' : '',
            'global/virustotalkey' : '',
        }

        info = self.db.execute( 'SELECT conf, value FROM configs WHERE conf IN %s', ( globalConf.keys(), ) )

        for row in info:
            globalConf[ row[ 0 ] ] = row[ 1 ]

        return ( True, globalConf )

    def set_config( self, msg ):
        self.log( 'set_config' )
        req = msg.data

        conf = req[ 'conf' ]
        value = req[ 'value' ]
        byUser = req[ 'by' ]

        info = self.db.execute( 'UPDATE configs SET value = %s WHERE conf = %s', ( conf, value ) )

        self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'conf_change', 'msg' : 'Config %s was changed by %s.' % ( conf, byUser ) } )

        return ( True, {} )

    def deploy_org( self, msg ):
        req = msg.data

        self.log( 'huhhh' )

        return ( True, {} )

    def get_c2_cert( self, msg ):
        self.log( 'get_c2_cert' )
        req = msg.data

        info = self.db.getOne( 'SELECT conf, value FROM configs WHERE conf = %s', ( 'key/c2', ) )

        if info is not None:
            return ( True, self.unpackKey( info[ 1 ] ) )

        return ( False, 'not found' )