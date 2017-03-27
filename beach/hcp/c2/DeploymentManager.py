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
import urllib2
from zipfile import ZipFile
from io import BytesIO
import random
CassDb = Actor.importLib( 'utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( 'utils/hcp_databases', 'CassPool' )
rSequence = Actor.importLib( 'utils/rpcm', 'rSequence' )
rList = Actor.importLib( 'utils/rpcm', 'rList' )
rpcm = Actor.importLib( 'utils/rpcm', 'rpcm' )

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
        self.admin = self.getActorHandle( resources[ 'admin' ] )

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

    def getSensorPackage( self ):
        packages = {}
        info = self.db.getOne( 'SELECT value FROM configs WHERE conf = %s', ( 'global/sensorpackage', ) )
        if not info or info[ 0 ] is None or info[ 0 ] == '':
            self.log( 'no sensor package defined' )
        else:
            with urllib2.urlopen( info[ 0 ] ) as pkgUrl:
                zipPackage = ZipFile( BytesIO( pkgUrl.read() ) )
                packages = { name: zipPackage.read( name ) for name in zipPackage.namelist() }
                del( zipPackage )
        return packages

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

    def setSensorConfig( self, sensor, config ):
        # This is the key also defined in the sensor as _HCP_DEFAULT_STATIC_STORE_KEY
        # and used with the same algorithm as obfuscationLib
        OBFUSCATION_KEY = "\xFA\x75\x01"
        STATIC_STORE_MAX_SIZE = 1024 * 50

        def obfuscate( buffer, key ):
            obf = BytesIO()
            index = 0
            for hx in buffer:
                obf.write( chr( ( ( ord( key[ index % len( key ) ] ) ^ ( index % 255 ) ) ^ ( STATIC_STORE_MAX_SIZE % 255 ) ) ^ ord( hx ) ) )
                index = index + 1
            return obf.getvalue()

        config = obfuscate( rpcm().serialise( config ), OBFUSCATION_KEY )

        magic = "\xFA\x57\xF0\x0D" + ( "\x00" * ( len( config ) - 4 ) )

        if magic not in sensor:
            return None

        sensor = sensor.replace( magic, config )

        return sensor


    def genBinariesForOrg( self, sensorPackage, oid ):
        rootPub = None
        rootPri = None
        hbsPub = None
        c2Cert = None

        iid = uuid.uuid4()

        info = self.db.getOne( 'SELECT value FROM configs WHERE conf = %s', ( 'key/root', ) )
        if not info or not info[ 0 ]:
            self.log( 'failed to get root key' )
            return False

        c2Key = self.unpackKey( info[ 0 ] )
        rootPub = c2Key[ 'pubDer' ]
        rootPri = c2Key[ 'priDer' ]
        del( c2Key )

        info = self.db.getOne( 'SELECT pub FROM hbs_keys WHERE oid = %s', ( oid, ) )
        if not info or not info[ 0 ]:
            self.log( 'failed to get hbs key' )
            return False

        hbsPub = info[ 0 ]

        info = self.db.getOne( 'SELECT value FROM configs WHERE conf = %s', ( 'key/c2', ) )
        if not info or not info[ 0 ]:
            self.log( 'failed to get c2 cert' )
            return False

        c2Cert = self.unpackKey( info[ 0 ] )[ 'pub' ]

        info = self.db.getOne( 'SELECT value FROM configs WHERE conf = %s', ( 'global/primary', ) )
        if not info or not info[ 0 ]:
            self.log( 'failed to get primary domain' )
            return False

        primaryDomain = info[ 0 ]

        info = self.db.getOne( 'SELECT value FROM configs WHERE conf = %s', ( 'global/primary_port', ) )
        if not info or not info[ 0 ]:
            self.log( 'failed to get primary port' )
            return False

        primaryPort = int( info[ 0 ] )

        info = self.db.getOne( 'SELECT value FROM configs WHERE conf = %s', ( 'global/secondary', ) )
        if not info or not info[ 0 ]:
            self.log( 'failed to get secondary domain' )
            return False

        secondaryDomain = info[ 0 ]

        info = self.db.getOne( 'SELECT value FROM configs WHERE conf = %s', ( 'global/secondary_port', ) )
        if not info or not info[ 0 ]:
            self.log( 'failed to get secondary port' )
            return False

        secondaryPort = int( info[ 0 ] )

        hcpConfig = ( rSequence().addStringA( _.hcp.PRIMARY_URL, primaryDomain )
                                 .addInt16( _.hcp.PRIMARY_PORT, primaryPort )
                                 .addStringA( _.hcp.SECONDARY_URL, secondaryDomain )
                                 .addInt16( _.hcp.SECONDARY_PORT, secondaryPort )
                                 .addSequence( _.base.HCP_IDENT, rSequence().addBuffer( _.base.HCP_ORG_ID, oid.bytes )
                                                                            .addBuffer( _.base.HCP_INSTALLER_ID, iid.bytes )
                                                                            .addBuffer( _.base.HCP_SENSOR_ID, uuid.UUID( '00000000-0000-0000-0000-000000000000' ).bytes )
                                                                            .addInt32( _.base.HCP_PLATFORM, 0 )
                                                                            .addInt32( _.base.HCP_ARCHITECTURE, 0 ) )
                                 .addBuffer( _.hcp.C2_PUBLIC_KEY, c2Cert )
                                 .addBuffer( _.hcp.ROOT_PUBLIC_KEY, rootPub ) )

        hbsConfig = ( rSequence().addBuffer( _.hbs.ROOT_PUBLIC_KEY, hbsPub ) )

        for binName, binary in sensorPackage.iteritems():
            if binName.startswith( 'hcp_' ):
                patched = self.setSensorConfig( binary, hcpConfig )
                if 'osx' in binName:
                    pass
            elif binName.startswith( 'hbs_' ):
                patched = self.setSensorConfig( binary, hbsConfig )
                

    def get_global_config( self, msg ):
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
        req = msg.data

        conf = req[ 'conf' ]
        value = req[ 'value' ]
        byUser = req[ 'by' ]

        info = self.db.execute( 'UPDATE configs SET value = %s WHERE conf = %s', ( value, conf ) )

        self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'conf_change', 'msg' : 'Config %s was changed by %s.' % ( conf, byUser ) } )

        return ( True, {} )

    def deploy_org( self, msg ):
        req = msg.data

        oid = uuid.UUID( req[ 'oid' ] )

        key = self.generateKey()
        resp = self.admin.request( 'hbs.add_key', { 'oid' : oid, 'key' : key[ 'priDer' ], 'pub_key' : key[ 'pubDer' ] } )
        if not resp.isSuccess:
            return ( False, resp.error )

        packages = self.getSensorPackage()

        if 0 == len( packages ):
            return ( False, 'no binaries in package or no package configured' )

        if not self.genBinariesForOrg( packages, oid ):
            return ( False, 'error generating binaries for org' )

        return ( True, {} )

    def get_c2_cert( self, msg ):
        req = msg.data

        info = self.db.getOne( 'SELECT conf, value FROM configs WHERE conf = %s', ( 'key/c2', ) )

        if info is not None:
            return ( True, self.unpackKey( info[ 1 ] ) )

        return ( False, 'not found' )