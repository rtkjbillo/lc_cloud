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
CassDb = Actor.importLib( 'utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( 'utils/hcp_databases', 'CassPool' )
Host = Actor.importLib( 'utils/ObjectsDb', 'Host' )
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )

class TaggingManager( Actor ):
    def init( self, parameters, resources ):
        self.admin = self.getActorHandle( resources[ 'admin' ] )
        Host.setDatabase( self.admin, parameters[ 'db' ] )

        self.sensorDir = self.getActorHandle( resources[ 'sensordir' ] )

        self.handle( 'get_tags', self.getTags )
        self.handle( 'add_tags', self.addTags )
        self.handle( 'del_tags', self.delTags )
        self.handle( 'search_tags', self.searchTags )

    def deinit( self ):
        Host.closeDatabase()

    def hostList( self, data ):
        if type( data ) not in ( list, tuple ):
            data = ( data, )
        return [ Host( x ) for x in data ]

    def tagList( self, data ):
        if type( data ) not in ( list, tuple ):
            data = ( data, )
        return [ str( x ) for x in data ]

    def getTags( self, msg ):
        req = msg.data
        hosts = self.hostList( req[ 'sid' ] )
        tagInfo = {}
        for host in hosts:
            tagInfo[ host.sid ] = host.getTags()

        return ( True, { 'tags' : tagInfo } )

    def addTags( self, msg ):
        req = msg.data

        hosts = self.hostList( req[ 'sid' ] )
        tags = self.tagList( req[ 'tag' ] )
        ttl = req.get( 'ttl', 60 * 60 * 24 * 365 )
        by = req.get( 'by', '' )

        endpointCache = {}
        sidCache = {}

        for host in hosts:
            for tag in tags:
                host.setTag( tag, by, ttl )

                endpointId = sidCache.get( host.sid, None )

                if endpointId is None:
                    resp = self.sensorDir.request( 'get_endpoint', { 'aid' : host.sid } )
                    if resp.isSuccess:
                        endpointId = resp.data[ 'endpoint' ]
                    sidCache[ host.sid ] = endpointId

                if endpointId is not None:
                    hEndpoint = endpointCache.get( endpointId, None )
                    if hEndpoint is None:
                        endpoint = self.getActorHandle( '_ACTORS/%s' % endpointId )
                        endpointCache[ endpointId ] = endpoint
                    if hEndpoint is not None:
                        hEndpoint.shoot( 'add_tag', { 'sid' : host.sid, 'tag' : tag } )

        for h in endpointCache.itervalues():
            h.close()

        return ( True, )

    def delTags( self, msg ):
        req = msg.data

        hosts = self.hostList( req[ 'sid' ] )
        tags = self.tagList( req[ 'tag' ] )
        by = req.get( 'by', '' )

        endpointCache = {}
        sidCache = {}

        for host in hosts:
            for tag in tags:
                host.unsetTag( tag )

                endpointId = sidCache.get( host.sid, None )

                if endpointId is None:
                    resp = self.sensorDir.request( 'get_endpoint', { 'aid' : host.sid } )
                    if resp.isSuccess:
                        endpointId = resp.data[ 'endpoint' ]
                    sidCache[ host.sid ] = endpointId

                if endpointId is not None:
                    hEndpoint = endpointCache.get( endpointId, None )
                    if hEndpoint is None:
                        endpoint = self.getActorHandle( '_ACTORS/%s' % endpointId )
                        endpointCache[ endpointId ] = endpoint
                    if hEndpoint is not None:
                        hEndpoint.shoot( 'del_tag', { 'sid' : host.sid, 'tag' : tag } )

        for h in endpointCache.itervalues():
            h.close()

        return ( True, )

    def searchTags( self, msg ):
        req = msg.data

        tag = req[ 'tag' ]
        orgs = req.get( 'oid', [] )

        sids = Host.getHostsWithTag( tag, inOrgs = orgs )

        return ( True, { 'hosts' : sids } )