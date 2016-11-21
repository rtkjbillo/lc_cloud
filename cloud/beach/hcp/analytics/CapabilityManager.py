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

synchronized = Actor.importLib( '../utils/hcp_helpers', 'synchronized' )

import urllib2
import json

class CapabilityManager( Actor ):
    def init( self, parameters, resources ):
        self.scale = parameters[ 'scale' ]
        self.patrol = Patrol( self._beach_config_path, 
                              realm = 'hcp', 
                              identifier = self.__class__.__name__,
                              scale = self.scale )
        self.patrol.start()
        self.detectSecretIdent = parameters[ 'detect_secret_ident' ]
        self.detectTrustedIdent = parameters[ 'detect_trusted_ident' ]
        self.hunterSecretIdent = parameters[ 'hunter_secret_ident' ]
        self.hunterTrustedIdent = parameters[ 'hunter_trusted_ident' ]
        self.loadedDetections = {}
        self.loadedPatrols = {}
        self.handle( 'load', self.loadCapability )
        self.handle( 'unload', self.unloadDetection )
        self.handle( 'list', self.listDetections )

    def deinit( self ):
        pass

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

    @synchronized
    def restartPatrol( self ):
        self.log( "restarting patrol" )
        self.patrol.stop()
        self.patrol.start()

    def ensureList( self, elem ):
        return ( elem, ) if type( elem ) not in ( list, tuple ) else elem

    def loadCapability( self, msg ):
        url = msg.data[ 'url' ]
        url = self.massageUrl( url )
        userDefinedName = msg.data[ 'user_defined_name' ]
        arguments = msg.data[ 'args' ]
        arguments = json.loads( arguments ) if ( arguments is not None and 0 != len( arguments ) ) else {}
        
        if userDefinedName in self.loadedDetections or userDefinedName in self.loadedPatrols:
            return ( False, 'user defined name already in use' )

        capability = urllib2.urlopen( url ).read()

        summary = self.getDetectionMtdFromContent( capability )
        if summary is not None:
            summary[ 'src' ] = url
            return self.loadDetection( msg, url, userDefinedName, arguments, summary )
        else:
            summary = self.getPatrolMtdFromContent( capability )
            if summary is not None:
                summary[ 'src' ] = url
                return self.loadPatrol( msg, url, userDefinedName, summary, capability )

        self.log( 'could not find any capability to load in url' )
        return ( False, 'could not find any capability to load in url' )

    def loadPatrol( self, msg, url, userDefinedName, summary, capability ):
        newPatrol = Patrol( self._beach_config_path, 
                            realm = 'hcp', 
                            identifier = userDefinedName,
                            scale = self.scale,
                            actorsRoot = url[ : url.rfind( '/' ) + 1 ] )

        newPatrol.loadFromUrl( url )

        summary[ 'instance' ] = newPatrol

        self.loadedPatrols[ userDefinedName ] = summary
        newPatrol.start()
        self.log( 'loading new patrol %s' % ( userDefinedName, ) )
        return ( True, summary )

    def loadDetection( self, msg, url, userDefinedName, arguments, summary ):
        summary[ 'name' ] = url.split( '/' )[ -1 ].lower().replace( '.py', '' )

        summary[ 'platform' ] = self.ensureList( summary[ 'platform' ] )
        if 'feeds' in summary:
            summary[ 'feeds' ] = self.ensureList( summary[ 'feeds' ] )

        categories = []
        secretIdent = None
        trustedIdents = None
        if 'stateless' == summary[ 'type' ]:
            secretIdent = self.detectSecretIdent
            trustedIdents = self.detectTrustedIdent
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
                                 'isIsolated' : summary.get( 'isIsolated', False ) } )

        self.loadedDetections[ userDefinedName ] = summary
        
        self.restartPatrol()
        self.log( 'loading new detection %s' % ( userDefinedName, ) )

        return ( True, summary )

    def unloadDetection( self, msg ):
        userDefinedName = msg.data[ 'user_defined_name' ]
        if userDefinedName in self.loadedDetections:
            removed = self.patrol.remove( userDefinedName, isStopToo = True )
            del( self.loadedDetections[ userDefinedName ] )
        elif userDefinedName in self.loadedPatrols:
            self.loadedPatrols[ userDefinedName ][ 'instance' ].stop()
            removedActors = self.loadedPatrols[ userDefinedName ][ 'instance' ].remove()
            removed = True
            del( self.loadedPatrols[ userDefinedName ] )
        return ( True, { 'removed' : removed } )

    def listDetections( self, msg ):
        return ( True, { 'loadedDetections' : self.loadedDetections,
                         'loadedPatrols' : self.loadedPatrols } )
