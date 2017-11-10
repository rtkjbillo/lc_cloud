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
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )

class TaskingRule( object ):
    def __init__( self, parent, aid, tag, compiledProfile, h ):
        self._parent = parent
        self._aid = AgentId( aid )
        self._compiledProfile = compiledProfile
        self._h = h
        self._tag = tag or ''

    def isMatch( self, aid ):
        if AgentId( aid ).inSubnet( self._aid ):
            return True
        return False

    def getInfo( self ):
        return ( self._compiledProfile, self._h )

    def getTag( self ):
        return self._tag

class HbsProfileManager( Actor ):
    def init( self, parameters, resources ):
        self.db = CassDb( parameters[ 'db' ], 'hcp_analytics' )

        self.loadProfiles = self.db.prepare( 'SELECT aid, tag, cprofile, hprofile FROM hbs_profiles' )

        self.profiles = []

        self.reloadProfiles()

        self.handle( 'sync', self.sync )
        self.handle( 'reload', self.reloadProfiles )

    def deinit( self ):
        self.db.shutdown()

    def sync( self, msg ):
        changes = {}
        aid = msg.data[ 'aid' ]
        tags = msg.data[ 'tags' ]
        currentProfileHash = msg.data[ 'hprofile' ].encode( 'hex' )

        # The algorithm here is that we return the first profile to match.
        # However, if a match has a tag match as well, it takes priority and
        # we return that first tag-match instead (more precise match).
        match = None
        for rule in self.profiles:
            if rule.isMatch( aid ):
                tag = rule.getTag()
                if '' == tag:
                    if match is None:
                        match = rule.getInfo()
                elif tag in tags:
                    match = rule.getInfo()
                    break
        
        if match is not None and match[ 1 ] != currentProfileHash:
            changes[ 'profile' ] = match

        return ( True, { 'changes' : changes } )

    def reloadProfiles( self, msg = None ):
        newProfiles = []
        for row in self.db.execute( self.loadProfiles.bind( tuple() ) ):
            newProfiles.append( TaskingRule( self, row[ 0 ], row[ 1 ], row[ 2 ], row[ 3 ] ) )

        self.profiles = newProfiles

        self.log( 'reloaded %d profiles' % ( len( newProfiles ), ) )

        return ( True, )
