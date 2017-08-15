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
from beach.patrol import Patrol

Mutex = Actor.importLib( '../utils/hcp_helpers', 'Mutex' )

import urllib2
import json
import tempfile

class CapabilityManager( Actor ):
    def init( self, parameters, resources ):
        self.scale = parameters[ 'scale' ]
        self.patrol = Patrol( self._beach_config_path, 
                              realm = 'hcp', 
                              identifier = self.__class__.__name__,
                              scale = self.scale,
                              sync_frequency = 60.0 )
        self.patrol.start()
        self.detectSecretIdent = parameters[ 'detect_secret_ident' ]
        self.detectTrustedIdent = parameters[ 'detect_trusted_ident' ]
        self.hunterSecretIdent = parameters[ 'hunter_secret_ident' ]
        self.hunterTrustedIdent = parameters[ 'hunter_trusted_ident' ]
        self.loadedDetections = {}
        self.loadedPatrols = {}
        self.storedConf = {}
        self.mutex = Mutex()
        self.deploymentmanager = self.getActorHandle( resources[ 'deployment' ], nRetries = 3, timeout = 30 )
        self.handle( 'load', self.loadCapability )
        self.handle( 'unload', self.unloadDetection )
        self.handle( 'list', self.listDetections )
        self.delay( 5, self.reloadStoredConfigs )

    def deinit( self ):
        pass

    def updateStoredConfigs( self ):
        resp = self.deploymentmanager.request( 'set_config', { 'conf' : 'global/capabilities', 
                                                               'value' : json.dumps( self.storedConf ), 
                                                               'by' : 'capability_manager' } )
        return resp.isSuccess

    def reloadStoredConfigs( self ):
        self.log( "Fetching existing capabilities." )
        resp = self.deploymentmanager.request( 'get_capabilities', {} )
        if resp.isSuccess:
            try:
                conf = json.loads( resp.data[ 'capabilities' ] )
            except:
                conf = {}
            self.storedConf = conf
            for confName, data in conf.iteritems():
                isSuccess, txt = self.doLoadCapability( data[ 'url' ], data[ 'content' ], data[ 'name' ], data[ 'args' ] )
                if isSuccess:
                    self.log( "Capability %s loaded from config store." % data[ 'name' ] )
                else:
                    self.log( "Error loading capability %s from config store: %s." % ( data[ 'name' ], txt ) )
        else:
            self.log( "No capabilities found." )

    def massageUrl( self, url ):
        if url.startswith( 'https://github.com/' ):
            url = url.replace( 'https://github.com/', 'https://raw.githubusercontent.com/' ).replace( '/blob/', '/' )
        return url

    def getDetectionMtdFromContent( self, detection ):
        mtd = []
        isMtdStarted = False
        for line in detection.split( '\n' ):
            if line.startswith( 'LC_DETECTION_MTD_START' ):
                isMtdStarted = True
            elif line.startswith( 'LC_DETECTION_MTD_END' ):
                break
            elif isMtdStarted:
                mtd.append( line )

        if 0 == len( mtd ):
            return None

        mtd = '\n'.join( mtd )

        mtd = json.loads( mtd )

        return mtd

    def getPatrolMtdFromContent( self, detection ):
        mtd = []
        isMtdStarted = False
        for line in detection.split( '\n' ):
            if line.startswith( 'LC_PATROL_MTD_START' ):
                isMtdStarted = True
            elif line.startswith( 'LC_PATROL_MTD_END' ):
                break
            elif isMtdStarted:
                mtd.append( line )

        if 0 == len( mtd ):
            return None

        mtd = '\n'.join( mtd )

        mtd = json.loads( mtd )

        return mtd

    def restartPatrol( self ):
        self.log( "restarting patrol" )
        self.patrol.stop()
        self.patrol.start()

    def ensureList( self, elem ):
        return ( elem, ) if type( elem ) not in ( list, tuple ) else elem

    def loadCapability( self, msg ):
        url = msg.data.get( 'url', None )
        patrolContent = msg.data.get( 'content', None )
        userDefinedName = msg.data[ 'user_defined_name' ]
        arguments = msg.data[ 'args' ]
        return self.doLoadCapability( url, patrolContent, userDefinedName, arguments )

    def doLoadCapability( self, url, patrolContent, userDefinedName, arguments ):
        with self.mutex:
            if url is not None:
                url = self.massageUrl( url )
            tmpStoredConf = { 'url' : url, 'content' : patrolContent, 'name' : userDefinedName, 'args' : arguments }
            arguments = json.loads( arguments ) if ( arguments is not None and 0 != len( arguments ) ) else {}
            
            if userDefinedName in self.loadedDetections or userDefinedName in self.loadedPatrols:
                return ( False, 'user defined name already in use' )

            if url is None:
                if patrolContent is None:
                    return ( False, 'no content provided' )
                else:
                    tmpPatrol = tempfile.NamedTemporaryFile( delete = False )
                    tmpPatrol.write( patrolContent )
                    url = 'file://%s' % tmpPatrol.name
                    tmpPatrol.close()

            capability = urllib2.urlopen( url ).read()

            summary = self.getDetectionMtdFromContent( capability )
            self.storedConf[ userDefinedName ] = tmpStoredConf
            try:
                if summary is not None:
                    summary[ 'src' ] = url
                    ret = self.loadDetection( url, userDefinedName, arguments, summary )
                    self.updateStoredConfigs()
                    return ret
                else:
                    summary = self.getPatrolMtdFromContent( capability )
                    if summary is not None:
                        summary[ 'src' ] = url
                        ret = self.loadPatrol( url, userDefinedName, summary, capability )
                        self.updateStoredConfigs()
                        return ret
            except:
                self.storedConf.pop( userDefinedName, None )
                raise

            self.log( 'could not find any capability to load in url' )
            return ( False, 'could not find any capability to load in url' )

    def loadPatrol( self, url, userDefinedName, summary, capability ):
        newPatrol = Patrol( self._beach_config_path, 
                            realm = 'hcp', 
                            identifier = userDefinedName,
                            scale = self.scale,
                            actorsRoot = url[ : url.rfind( '/' ) + 1 ],
                            sync_frequency = 60.0 )

        newPatrol.loadFromUrl( url )

        summary[ 'instance' ] = newPatrol

        self.loadedPatrols[ userDefinedName ] = summary
        newPatrol.start()
        self.log( 'loading new patrol %s' % ( userDefinedName, ) )
        return ( True, summary )

    def loadDetection( self, url, userDefinedName, arguments, summary ):
        summary[ 'name' ] = url.split( '/' )[ -1 ].lower().replace( '.py', '' )

        summary[ 'platform' ] = self.ensureList( summary[ 'platform' ] )
        if 'feeds' in summary:
            summary[ 'feeds' ] = self.ensureList( summary[ 'feeds' ] )

        categories = []
        secretIdent = None
        trustedIdents = None
        isDrainable = False
        if 'stateless' == summary[ 'type' ]:
            secretIdent = self.detectSecretIdent
            trustedIdents = self.detectTrustedIdent
            isDrainable = True
            for feed in summary[ 'feeds' ]:
                for platform in summary[ 'platform' ]:
                    categories.append( 'analytics/stateless/%s/%s/%s/%s' %  ( platform, 
                                                                              feed,
                                                                              summary[ 'name' ],
                                                                              summary[ 'version' ] ) )
        elif 'stateful' == summary[ 'type' ]:
            secretIdent = self.detectSecretIdent
            trustedIdents = self.detectTrustedIdent
            for platform in summary[ 'platform' ]:
                categories.append( 'analytics/stateful/modules/%s/%s/%s' %  ( platform,
                                                                              summary[ 'name' ],
                                                                              summary[ 'version' ] ) )
        elif 'hunter' == summary[ 'type' ]:
            secretIdent = self.hunterSecretIdent
            trustedIdents = self.hunterTrustedIdent
            categories.append( 'analytics/hunter/%s/%s' %  ( summary[ 'name' ],
                                                             summary[ 'version' ] ) )
        else:
            self.logCritical( 'unknown actor type' )

        self.patrol.monitor( name = userDefinedName,
                             initialInstances = 1,
                             scalingFactor = summary[ 'scaling_factor' ],
                             actorArgs = ( url, categories ),
                             actorKwArgs = {
                                 'parameters' : arguments,
                                 'secretIdent' : secretIdent,
                                 'trustedIdents' : trustedIdents,
                                 'n_concurrent' : summary.get( 'n_concurrent', 5 ),
                                 'isIsolated' : summary.get( 'isIsolated', False ),
                                 'is_drainable' : isDrainable } )

        self.loadedDetections[ userDefinedName ] = summary
        
        self.restartPatrol()
        self.log( 'loading new detection %s' % ( userDefinedName, ) )

        return ( True, summary )

    def unloadDetection( self, msg ):
        with self.mutex:
            userDefinedName = msg.data[ 'user_defined_name' ]
            removed = False
            if userDefinedName in self.loadedDetections:
                removed = self.patrol.remove( userDefinedName, isStopToo = True )
                del( self.loadedDetections[ userDefinedName ] )
            elif userDefinedName in self.loadedPatrols:
                self.loadedPatrols[ userDefinedName ][ 'instance' ].stop()
                removedActors = self.loadedPatrols[ userDefinedName ][ 'instance' ].remove()
                removed = True
                del( self.loadedPatrols[ userDefinedName ] )
            self.storedConf.pop( userDefinedName, None )
            self.updateStoredConfigs()
            return ( True, { 'removed' : removed } )

    def listDetections( self, msg ):
        with self.mutex:
            return ( True, { 'loadedDetections' : self.loadedDetections,
                             'loadedPatrols' : self.loadedPatrols } )

