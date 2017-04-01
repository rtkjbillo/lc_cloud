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
import json
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
HcpModuleId = Actor.importLib( 'utils/hcp_helpers', 'HcpModuleId' )
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )
Symbols = Actor.importLib( 'Symbols', 'Symbols' )()

class Signing( object ):
    
    def __init__( self, privateKey ):
        self.pri_key = None
        if not privateKey.startswith( '-----BEGIN RSA PRIVATE KEY-----' ):
            privateKey = self.der2pem( privateKey )
            
        self.pri_key = M2Crypto.RSA.load_key_string( privateKey )
    
    
    def sign( self, buff ):
        sig = None
        h = hashlib.sha256( buff ).digest()
        
        sig = self.pri_key.private_encrypt( h, M2Crypto.RSA.pkcs1_padding )
        
        return sig
    
    def der2pem( self, der ):
        encoded = base64.b64encode( der )
        encoded = [ encoded[ i : i + 64 ] for i in range( 0, len( encoded ), 64 ) ]
        encoded = '\n'.join( encoded )
        pem = '-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----\n' % encoded
        
        return pem

class DeploymentManager( Actor ):
    def init( self, parameters, resources ):
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

        isSuccess, _oid = self.get_global_config( None )
        if isSuccess:
            self.admin_oid = uuid.UUID( str( _oid[ 'global/admin_oid' ] ) )
        else:
            self.admin_oid = None

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

    def getMaskFor( self, oid, binName ):
        aid = AgentId( '0.0.0.0.0' )
        aid.org_id = oid
        if 'x64' in binName:
            aid.architecture = AgentId.ARCHITECTURE_X64
        else:
            aid.architecture = AgentId.ARCHITECTURE_X86

        if 'osx' in binName:
            aid.platform = AgentId.PLATFORM_MACOS
        elif 'win' in binName:
            aid.platform = AgentId.PLATFORM_WINDOWS
        elif 'ios' in binName:
            aid.platform = AgentId.PLATFORM_IOS
        elif 'android' in binName:
            aid.platform = AgentId.PLATFORM_ANDROID
        elif 'ubuntu' in binName:
            aid.platform = AgentId.PLATFORM_LINUX

        return aid

    def getSensorPackage( self ):
        packages = {}
        info = self.db.getOne( 'SELECT value FROM configs WHERE conf = %s', ( 'global/sensorpackage', ) )
        if not info or info[ 0 ] is None or info[ 0 ] == '':
            self.log( 'no sensor package defined' )
        else:
            pkgUrl = urllib2.urlopen( info[ 0 ] )
            zipPackage = ZipFile( BytesIO( pkgUrl.read() ) )
            packages = { name: zipPackage.read( name ) for name in zipPackage.namelist() }
        return packages

    def generateOsxAppBundle( self, binName, binary, osxAppBundle ):
        workingDir = tempfile.mkdtemp()
        bundlePath = os.path.join( workingDir, 'bundle.tar.gz' )
        appDir = os.path.join( workingDir, 'limacharlie.app' )
        finalBundle = '%s.app.tar.gz' % os.path.join( workingDir, binName )
        with open( bundlePath, 'wb' ) as f:
            f.write( osxAppBundle )
        
        if 0 != os.system( 'tar xzf %s -C %s' % ( bundlePath, workingDir ) ):
            raise Exception( 'error expanding osx app bundle on disk' )

        with open( os.path.join( appDir, 'Contents', 'MacOS', 'rphcp' ), 'wb' ) as f:
            f.write( binary )

        if 0 != os.system( 'tar zcf %s %s' % ( finalBundle, appDir ) ):
            raise Exception( 'error tar-ing osx app bundle on disk' )

        with open( finalBundle, 'rb' ) as f:
            binary = f.read()

        return binary

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
            adminOid = uuid.uuid4()
            uiDomain = 'limacharlie'
            try:
                resp = json.loads( urllib2.urlopen( 'https://api.github.com/repos/refractionPOINT/limacharlie/releases/latest' ).read() )
                sensorPackage = resp[ 'assets' ][ 0 ][ 'browser_download_url' ]
            except:
                sensorpackage = ''
            self.admin_oid = adminOid
            self.log( 'loading admin oid' )
            self.db.execute( 'INSERT INTO configs ( conf, value ) VALUES ( %s, %s )', ( 'global/admin_oid', str( adminOid ) ) )
            self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'conf_change', 'msg' : 'New admin oid generated.' } )

            self.log( 'loading ui domain' )
            self.db.execute( 'INSERT INTO configs ( conf, value ) VALUES ( %s, %s )', ( 'global/uidomain', uiDomain ) )
            self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'conf_change', 'msg' : 'Setting ui domain.' } )

            self.log( 'loading current latest sensor package version' )
            self.db.execute( 'INSERT INTO configs ( conf, value ) VALUES ( %s, %s )', ( 'global/sensorpackage', sensorPackage ) )
            self.audit.shoot( 'record', { 'oid' : self.admin_oid, 'etype' : 'conf_change', 'msg' : 'Setting sensor package.' } )
            
            self.log( 'loading root key' )
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


    def genBinariesForOrg( self, sensorPackage, oid, osxAppBundle = None ):
        rootPub = None
        rootPri = None
        hbsPub = None
        c2Cert = None

        iid = uuid.uuid4()

        info = self.db.getOne( 'SELECT value FROM configs WHERE conf = %s', ( 'key/root', ) )
        if not info or not info[ 0 ]:
            self.log( 'failed to get root key' )
            return False

        rootKey = self.unpackKey( info[ 0 ] )
        rootPub = rootKey[ 'pubDer' ]
        rootPri = rootKey[ 'priDer' ]
        del( rootKey )

        info = self.db.getOne( 'SELECT pub FROM hbs_keys WHERE oid = %s', ( oid, ) )
        if not info or not info[ 0 ]:
            self.log( 'failed to get hbs key' )
            return False

        hbsPub = info[ 0 ]

        info = self.db.getOne( 'SELECT value FROM configs WHERE conf = %s', ( 'key/c2', ) )
        if not info or not info[ 0 ]:
            self.log( 'failed to get c2 cert' )
            return False

        c2Cert = self.unpackKey( info[ 0 ] )[ 'cert' ]

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

        _ = Symbols

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

        signing = Signing( rootPri )

        installersToLoad = {}
        hbsToLoad = {}
        kernelToLoad = {}

        for binName, binary in sensorPackage.iteritems():
            if binName.startswith( 'hcp_' ):
                patched = self.setSensorConfig( binary, hcpConfig )
                if 'osx' in binName and osxAppBundle is not None:
                    patched = self.generateOsxAppBundle( binName, binary, osxAppBundle )
                installersToLoad[ binName ] = patched
            elif binName.startswith( 'hbs_' ) and 'release' in binName:
                patched = self.setSensorConfig( binary, hbsConfig )
                hbsToLoad[ binName ] = ( patched, signing.sign( patched ), hashlib.sha256( patched ).hexdigest() )
            elif binName.startswith( 'kernel_' ) and 'release' in binName:
                kernelToLoad[ binName ] = ( binary, signing.sign( binary ), hashlib.sha256( patched ).hexdigest() )

        self.log( 'binaries for %s have been generated, loading them' % oid )

        resp =  self.admin.request( 'hcp.remove_installer', { 'oid' : oid } )
        if not resp.isSuccess:
            self.log( 'error wiping previous installers: %s' % resp )
            return False

        for binName, binary in installersToLoad.iteritems():
            resp = self.admin.request( 'hcp.add_installer', { 'oid' : oid, 
                                                              'iid' : iid, 
                                                              'description' : binName, 
                                                              'installer' : binary } )
            if not resp.isSuccess:
                self.log( 'error loading new installer for %s' % oid )
                return False

        resp =  self.admin.request( 'hcp.remove_tasking', { 'oid' : oid } )
        if not resp.isSuccess:
            self.log( 'error wiping previous taskings: %s' % resp )
            return False
            
        for binName, binInfo in hbsToLoad.iteritems():
            binary, binSig, binHash = binInfo
            aid = self.getMaskFor( oid, binName )
            resp = self.admin.request( 'hcp.add_module', { 'module_id' : HcpModuleId.HBS,
                                                           'hash' : binHash,
                                                           'bin' : binary,
                                                           'signature' : binSig } )
            if resp.isSuccess:
                resp = self.admin.request( 'hcp.add_tasking', { 'mask' : aid.asString(),
                                                                'module_id' : HcpModuleId.HBS,
                                                                'hash' : binHash } )
                if not resp.isSuccess:
                    self.log( 'error tasking new hbs module: %s' % resp )
                    return False
            else:
                self.log( 'error adding new hbs module: %s' % resp )
                return False

        for binName, binInfo in kernelToLoad.iteritems():
            binary, binSig, binHash = binInfo
            aid = self.getMaskFor( oid, binName )
            resp = self.admin.request( 'hcp.add_module', { 'module_id' : HcpModuleId.KERNEL_ACQ,
                                                           'hash' : binHash,
                                                           'bin' : binary,
                                                           'signature' : binSig } )
            if resp.isSuccess:
                resp = self.admin.request( 'hcp.add_tasking', { 'mask' : aid.asString(),
                                                                'module_id' : HcpModuleId.KERNEL_ACQ,
                                                                'hash' : binHash } )
                if not resp.isSuccess:
                    self.log( 'error tasking new kernel module: %s' % resp )
                    return False
            else:
                self.log( 'error adding new kernel module: %s' % resp )
                return False

        return True

    def get_global_config( self, msg ):
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
            'global/uidomain' : '',
            'global/admin_oid' : '',
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

        isGenerateKey = req.get( 'is_generate_key', True )

        oid = uuid.UUID( req[ 'oid' ] )

        if isGenerateKey:
            key = self.generateKey()
            resp = self.admin.request( 'hbs.add_key', { 'oid' : oid, 'key' : key[ 'priDer' ], 'pub_key' : key[ 'pubDer' ] } )
            if not resp.isSuccess:
                return ( False, resp.error )

        packages = self.getSensorPackage()

        if 0 == len( packages ):
            return ( False, 'no binaries in package or no package configured' )

        if not self.genBinariesForOrg( packages, oid, osxAppBundle = self.readRelativeFile( 'resources/osx_app_bundle.tar.gz' ) ):
            return ( False, 'error generating binaries for org' )

        return ( True, {} )

    def get_c2_cert( self, msg ):
        req = msg.data

        info = self.db.getOne( 'SELECT conf, value FROM configs WHERE conf = %s', ( 'key/c2', ) )

        if info is not None:
            return ( True, self.unpackKey( info[ 1 ] ) )

        return ( False, 'not found' )
