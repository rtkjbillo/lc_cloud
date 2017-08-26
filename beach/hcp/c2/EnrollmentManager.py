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
import hmac
import uuid
from sets import Set
from io import BytesIO
CassDb = Actor.importLib( 'utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( 'utils/hcp_databases', 'CassPool' )
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )
rpcm = Actor.importLib( 'utils/rpcm', 'rpcm' )
rList = Actor.importLib( 'utils/rpcm', 'rList' )
rSequence = Actor.importLib( 'utils/rpcm', 'rSequence' )
Signing = Actor.importLib( 'signing', 'Signing' )
_ = Actor.importLib( 'Symbols', 'Symbols' )()

# This is the key also defined in the sensor as _HCP_DEFAULT_STATIC_STORE_KEY
# and used with the same algorithm as obfuscationLib
OBFUSCATION_KEY = "\xFA\x75\x01"

class EnrollmentManager( Actor ):
    def init( self, parameters, resources ):
        self.enrollmentKey = parameters.get( 'enrollment_token', 'DEFAULT_HCP_ENROLLMENT_TOKEN' )
        self._db = CassDb( parameters[ 'db' ], 'hcp_analytics', consistencyOne = True )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )

        self.db.start()

        self.deploymentManager = self.getActorHandle( resources[ 'deployment' ], nRetries = 3, timeout = 10 )
        self.tagging = self.getActorHandle( resources[ 'tagging' ], timeout = 10, nRetries = 3 )

        self.installers = {}
        self.c2Key = None
        self.rootKey = None
        self.primary = ( None, None )
        self.secondary = ( None, None )

        self.rpcm = rpcm( isHumanReadable = True, isDebug = self.log )
        self.signing = None

        self.schedule( 3600, self.loadRules )

        self.handle( 'enroll', self.enroll )
        self.handle( 'authorize', self.authorize )
        self.handle( 'reload', self.loadRules )

    def deinit( self ):
        pass

    def loadRules( self, msg = None ):
        newRules = []

        resp = self.deploymentManager.request( 'get_c2_cert', {} )
        if resp.isSuccess:
            self.c2Key = resp.data[ 'cert' ]

        resp = self.deploymentManager.request( 'get_root_cert', {} )
        if resp.isSuccess:
            self.rootKey = resp.data[ 'pubDer' ]
            self.signing = signing = Signing( resp.data[ 'priDer' ] )

        resp = self.deploymentManager.request( 'get_global_config', {} )
        if resp.isSuccess:
            self.primary = ( resp.data[ 'global/primary' ], resp.data[ 'global/primary_port' ] )
            self.secondary = ( resp.data[ 'global/secondary' ], resp.data[ 'global/secondary_port' ] )

        for row in self.db.execute( 'SELECT oid, iid FROM hcp_installers' ):
            self.installers[ ( row[ 0 ], row[ 1 ] ) ] = ( '', [] )

        for row in self.db.execute( 'SELECT oid, iid, description, tags FROM hcp_whitelist' ):
            tags = ( row[ 3 ] if row[ 3 ] is not None else '' ).split( ',' )
            self.installers[ ( row[ 0 ], row[ 1 ] ) ] = ( row[ 2 ], tags )

    def getTokenFor( self, aid ):
        h = hmac.new( self.enrollmentKey, aid.asString(), hashlib.sha256 )
        return h.digest()

    def obfuscate( self, buffer, key ):
        obf = BytesIO()
        index = 0
        for hx in buffer:
            obf.write( chr( ( ( ord( key[ index % len( key ) ] ) ^ ( index % 255 ) ) ^ ( len( buffer ) % 255 ) ) ^ ord( hx ) ) )
            index = index + 1
        return obf.getvalue()

    def enroll( self, msg ):
        req = msg.data

        aid = AgentId( req[ 'aid' ] )

        installerInfo = self.installers.get( ( aid.org_id, aid.ins_id ), None )

        if installerInfo is None:
            return ( True, { 'aid' : None } )

        extIp = req[ 'public_ip' ]
        intIp = req[ 'internal_ip' ]
        hostName = req[ 'host_name' ]

        aid.sensor_id = uuid.uuid4()

        self.db.execute( 'INSERT INTO sensor_states ( sid, oid, iid, plat, arch, enroll ) VALUES ( %s, %s, %s, %s, %s, dateOf( now() ) )', 
                         ( aid.sensor_id, aid.org_id, aid.ins_id, aid.platform, aid.architecture ) )

        self.db.execute( 'INSERT INTO org_sensors ( oid, iid, sid ) VALUES ( %s, %s, %s )', 
                         ( aid.org_id, aid.ins_id, aid.sensor_id ) )

        enrollmentToken = self.getTokenFor( aid )

        # Assemble the config store sent to the new sensor.
        conf = ( rSequence().addStringA( _.hcp.PRIMARY_URL, self.primary[ 0 ] )
                            .addInt16( _.hcp.PRIMARY_PORT, self.primary[ 1 ] )
                            .addStringA( _.hcp.SECONDARY_URL, self.secondary[ 0 ] )
                            .addInt16( _.hcp.SECONDARY_PORT, self.secondary[ 1 ] )
                            .addSequence( _.base.HCP_IDENT, rSequence().addBuffer( _.base.HCP_ORG_ID, aid.org_id.bytes )
                                                                       .addBuffer( _.base.HCP_INSTALLER_ID, aid.ins_id.bytes )
                                                                       .addBuffer( _.base.HCP_SENSOR_ID, uuid.UUID( '00000000-0000-0000-0000-000000000000' ).bytes )
                                                                       .addInt32( _.base.HCP_PLATFORM, 0 )
                                                                       .addInt32( _.base.HCP_ARCHITECTURE, 0 ) )
                            .addBuffer( _.hcp.C2_PUBLIC_KEY, self.c2Key )
                            .addBuffer( _.hcp.ROOT_PUBLIC_KEY, self.rootKey ) )
        conf = self.rpcm.serialise( conf )
        conf = self.obfuscate( conf, OBFUSCATION_KEY )
        confSig = self.signing.sign( conf )

        # Now apply all tags associated with that installer id.
        desc, tags = installerInfo
        if 0 != len( tags ):
            self.tagging.shoot( 'add_tags', { 'sid' : aid.sensor_id, 'tag' : tags, 'ttl' : 60 * 60 * 24 * 365 * 20, 'by' : 'enroll' } )

        return ( True, { 'aid' : aid, 
                         'token' : enrollmentToken, 
                         'conf' : conf,
                         'conf_sig' : confSig } )

    def authorize( self, msg ):
        req = msg.data

        aid = AgentId( req[ 'aid' ] )
        token = req[ 'token' ]

        isAuthorized = False

        expectedEnrollmentToken = self.getTokenFor( aid )
        
        if hmac.compare_digest( token, expectedEnrollmentToken ):
            isAuthorized = True

        return ( True, { 'is_authorized' : isAuthorized } )