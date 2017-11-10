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

from beach.beach_api import Beach
import json
import hashlib
import uuid
try:
    # When used by the random python script
    # import normally
    from rpcm import rpcm
    from rpcm import rSequence
    from rpcm import rList
    from Symbols import Symbols
    from signing import Signing
    from hcp_helpers import AgentId
except:
    # When in an actor, use the relative import
    from beach.actor import Actor
    rpcm = Actor.importLib( 'utils/rpcm', 'rpcm' )
    rSequence = Actor.importLib( 'utils/rpcm', 'rSequence' )
    rList = Actor.importLib( 'utils/rpcm', 'rList' )
    Symbols = Actor.importLib( 'Symbols', 'Symbols' )
    Signing = Actor.importLib( 'signing', 'Signing' )
    AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )

#===============================================================================
# Library section to be used by Python code for automation
#===============================================================================
class BEAdmin( object ):
    token = None
    
    def __init__( self, beach_config, token, timeout = 1000 * 10 ):
        self.token = token
        self.empty_uuid = uuid.UUID( bytes = "\x00" * 16 )
        self.beach = Beach( beach_config, realm = 'hcp' )
        self.vHandle = self.beach.getActorHandle( 'c2/admin/1.0',
                                                  ident = 'cli/955f6e63-9119-4ba6-a969-84b38bfbcc05',
                                                  timeout = timeout,
                                                  nRetries = 3 )

    def _query( self, cmd, data = {} ):
        data[ 'token' ] = self.token
        response = self.vHandle.request( cmd, data )
        return response
    
    def testConnection( self ):
        return self._query( 'ping' )
    
    def hcp_getAgentStates( self, aid = None, hostname = None ):
        filters = {}
        if aid is not None:
            filters[ 'aid' ] = aid
        if hostname is not None:
            filters[ 'hostname' ] = hostname
        return self._query( 'hcp.get_agent_states', filters )
    
    def hcp_getTaskings( self, oid = None ):
        return self._query( 'hcp.get_taskings', { 'oid' : oid } )
    
    def hcp_addTasking( self, mask, moduleId, hashStr ):
        return self._query( 'hcp.add_tasking', { 'mask' : mask, 'module_id' : int( moduleId ), 'hash' : hashStr } )
    
    def hcp_delTasking( self, mask, moduleId ):
        return self._query( 'hcp.remove_tasking', { 'mask' : mask, 'module_id' : int( moduleId ) } )
    
    def hcp_getModules( self ):
        return self._query( 'hcp.get_modules' )
    
    def hcp_addModule( self, moduleId, binary, signature, description ):
        return self._query( 'hcp.add_module', { 'module_id' : moduleId, 'bin' : binary, 'signature' : signature, 'hash' : hashlib.sha256( binary ).hexdigest(), 'description' : description } )
    
    def hcp_delModule( self, moduleId, hashStr ):
        return self._query( 'hcp.remove_module', { 'module_id' : moduleId, 'hash' : hashStr } )

    def hcp_getInstallers( self, oid = None, iid = None, hash = None, withContent = False ):
        return self._query( 'hcp.get_installers', { 'with_content' : withContent, 'oid' : oid, 'iid' : iid, 'hash' : hash } )
    
    def hcp_addInstaller( self, oid, iid, description, installer ):
        return self._query( 'hcp.add_installer', { 'oid' : oid, 'iid' : iid, 'description' : description, 'installer' : installer } )
    
    def hcp_delInstaller( self, oid, iid, hash ):
        return self._query( 'hcp.remove_installer', { 'oid' : oid, 'iid' : iid, 'hash' : hash } )

    def hcp_getWhitelist( self, oid = None, iid = None ):
        return self._query( 'hcp.get_whitelist', { 'oid' : oid, 'iid' : iid } )
    
    def hcp_addWhitelist( self, oid, iid, bootstrap ):
        return self._query( 'hcp.add_whitelist', { 'oid' : oid, 'iid' : iid, 'bootstrap' : bootstrap } )
    
    def hcp_delWhitelist( self, oid, iid ):
        return self._query( 'hcp.remove_whitelist', { 'oid' : oid, 'iid' : iid } )
    
    def hbs_getProfiles( self, oid = [] ):
        return self._query( 'hbs.get_profiles', { 'oid' : oid } )
    
    def hbs_addProfile( self, mask, config, tag ):
        return self._query( 'hbs.set_profile', { 'mask' : mask, 'module_configs' : config, 'tag' : tag } )
    
    def hbs_delProfile( self, mask ):
        return self._query( 'hbs.del_profile', { 'mask' : mask } )
    
    def hbs_taskAgent( self, toAgent, task, key, id, expiry = None, investigationId = None ):
        # Make sure it's a valid agentid
        a = AgentId( toAgent )
        if not type( task ) is rSequence:
            return None
        s = Signing( key )
        r = rpcm( isHumanReadable = True, isDebug = True )
        
        tags = Symbols()
        
        if investigationId is not None and '' != investigationId:
            task.addStringA( tags.hbs.INVESTIGATION_ID, investigationId )
        
        toSign = ( rSequence().addSequence( tags.base.HCP_IDENT, rSequence().addBuffer( tags.base.HCP_SENSOR_ID, 
                                                                                        ( a.sensor_id if a.sensor_id is not None else self.empty_uuid ).bytes )
                                                                            .addBuffer( tags.base.HCP_ORG_ID, 
                                                                                        ( a.org_id if a.org_id is not None else self.empty_uuid ).bytes )
                                                                            .addBuffer( tags.base.HCP_INSTALLER_ID, 
                                                                                         ( a.ins_id if a.ins_id is not None else self.empty_uuid ).bytes )
                                                                            .addInt32( tags.base.HCP_ARCHITECTURE, 
                                                                                       a.architecture if a.architecture is not None else 0 )
                                                                            .addInt32( tags.base.HCP_PLATFORM, 
                                                                                       a.platform if a.platform is not None else 0 ) )
                              .addSequence( tags.hbs.NOTIFICATION, task )
                              .addInt32( tags.hbs.NOTIFICATION_ID, id ) )
        if None != expiry:
            toSign.addTimestamp( tags.base.EXPIRY, int( expiry ) )
        toSign = r.serialise( toSign )
        sig = s.sign( toSign )
        
        final = r.serialise( rSequence().addBuffer( tags.base.BINARY, toSign )
                                        .addBuffer( tags.base.SIGNATURE, sig ) )
        
        return self._query( 'hbs.task_agent', { 'task' : final, 'aid' : str( a ), 'expiry' : expiry } )

    def hbs_addKey( self, oid, key ):
        return self._query( 'hbs.add_key', { 'oid' : oid, 'key' : key } )
