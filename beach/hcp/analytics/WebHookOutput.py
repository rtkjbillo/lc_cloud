# Copyright 2017 Google, Inc
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

import os
import json
import uuid
import base64
import urllib
import urllib2
from sets import Set

AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )

class WebHookOutput( Actor ):
    def init( self, parameters, resources ):
        self.deploymentManager = self.getActorHandle( resources[ 'deployment' ], nRetries = 3, timeout = 30 )
        self.identManager = self.getActorHandle( resources[ 'identmanager' ], nRetries = 3, timeout = 30 )

        self.hooks = {}

        self.refreshHooks()

        self.handle( 'report_inv', self.reportDetectOrInv )
        self.handle( 'report_detect', self.reportDetectOrInv )
        
    def deinit( self ):
        pass

    def refreshHooks( self ):
        allOrgs = self.identManager.request( 'get_org_info', { 'include_all' : True } )
        if allOrgs.isSuccess:
            for oName, oid, _ in allOrgs.data[ 'orgs' ]:
                oid = uuid.UUID( oid )
                oConf = self.deploymentManager.request( 'get_org_config', { 'oid' : oid } )
                if oConf.isSuccess:
                    hookSecret = oConf.data[ '%s/webhook_secret' % oid ]
                    hookDest = oConf.data[ '%s/webhook_dest' % oid ]
                    self.hooks[ oid ] = ( hookDest, hookSecret )

        self.delay( 60, self.refreshHooks )

    def sanitizeJson( self, o ):
        if type( o ) is dict:
            for k, v in o.iteritems():
                o[ k ] = self.sanitizeJson( v )
        elif type( o ) is list or type( o ) is tuple:
            o = [ self.sanitizeJson( x ) for x in o ]
        elif type( o ) is uuid.UUID:
            o = str( o )
        else:
            try:
                if ( type(o) is str or type(o) is unicode ) and "\x00" in o: raise Exception()
                json.dumps( o )
            except:
                o = base64.b64encode( o )

        return o

    def reportDetectOrInv( self, msg ):
        record = msg.data

        record = self.sanitizeJson( record )

        sources = map( AgentId, record[ 'source' ].split( ' / ' ) )
        
        sent = Set()
        for source in sources:
            dest, secret = self.hooks.get( source.org_id, ( '', None ) )
            if '' != dest and source.org_id not in sent:
                sent.add( source.org_id )
                hookType = 'investigation' if 'hunter' in record else 'detection'
                try:
                    result = urllib2.urlopen( urllib2.Request( dest, 
                                                               json.dumps( { 'secret' : secret, 
                                                                             'oid' : str( source.org_id ),
                                                                             'type' : hookType, 
                                                                             'data' : record } ),
                                                               { 'Content-Type': 'application/json' } ),
                                              timeout = 4 ).read()
                    self.log( "hook sent for %s" % dest )
                except:
                    self.log( "Failed to send webhook for org %s at %s" % ( source.org_id, dest ) )

        return ( True, )