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
        self.patrol = Patrol( parameters[ 'beach_config' ], 
                              realm = 'hcp', 
                              identifier = self.__class__.__name__,
                              scale = parameters[ 'scale' ] )
        self.patrol.start()
        self.detectSecretIdent = parameters[ 'detect_secret_ident' ]
        self.detectTrustedIdent = parameters[ 'detect_trusted_ident' ]
        self.hunterSecretIdent = parameters[ 'hunter_secret_ident' ]
        self.hunterTrustedIdent = parameters[ 'hunter_trusted_ident' ]
        self.loaded = {}
        self.handle( 'load', self.loadDetection )
        self.handle( 'unload', self.unloadDetection )
        self.handle( 'list', self.listDetections )

    def deinit( self ):
        pass

    def getMtdFromContent( self, detection ):
        mtd = []
        isMtdStarted = False
        for line in detection.split( '\n' ):
            if line.startswith( 'LC_DETECTION_MTD_START' ):
                isMtdStarted = True
            elif line.startswith( 'LC_DETECTION_MTD_END' ):
                break
            elif isMtdStarted:
                mtd.append( line )

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

    def loadDetection( self, msg ):
        url = msg.data[ 'url' ]
        userDefinedName = msg.data[ 'user_defined_name' ]
        arguments = msg.data[ 'args' ]
        arguments = json.loads( arguments ) if ( arguments is not None and 0 != len( arguments ) ) else {}

        if userDefinedName in self.loaded:
            return ( False, 'user defined name already in use' )

        detection = urllib2.urlopen( url ).read()

        summary = {}
        summary = self.getMtdFromContent( detection )
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
                                 'n_concurrent' : summary.get( 'n_concurrent', 5 ) } )

        self.loaded[ userDefinedName ] = summary
        
        self.restartPatrol()
        self.log( 'loading new detection %s' % ( userDefinedName, ) )

        return ( True, summary )

    def unloadDetection( self, msg ):
        userDefinedName = msg.data[ 'user_defined_name' ]
        removed = self.patrol.remove( userDefinedName, isStopToo = True )
        del( self.loaded[ userDefinedName ] )
        return ( True, { 'removed' : removed } )

    def listDetections( self, msg ):
        return ( True, { 'loaded' : self.loaded } )
