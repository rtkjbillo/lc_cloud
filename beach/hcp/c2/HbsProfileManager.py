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
    def __init__( self, parent, aid, compiledProfile, h ):
        self._parent = parent
        self._aid = AgentId( aid )
        self._compiledProfile = compiledProfile
        self._h = h

    def isMatch( self, aid ):
        if not AgentId( aid ).inSubnet( self._aid ):
            return False
        return ( self._compiledProfile, self._h )

class HbsProfileManager( Actor ):
    def init( self, parameters, resources ):
        self.db = CassDb( parameters[ 'db' ], 'hcp_analytics' )

        self.loadProfiles = self.db.prepare( 'SELECT aid, cprofile, hprofile FROM hbs_profiles' )

        self.profiles = []

        self.reloadProfiles()

        self.handle( 'sync', self.sync )
        self.handle( 'reload', self.reloadProfiles )

    def deinit( self ):
        self.db.shutdown()

    def sync( self, msg ):
        changes = {}
        aid = msg.data[ 'aid' ]
        currentProfileHash = msg.data[ 'hprofile' ].encode( 'hex' )

        for rule in self.profiles:
            match = rule.isMatch( aid )
            if match is not False:
                if match[ 1 ] != currentProfileHash:
                    changes[ 'profile' ] = match
                break

        return ( True, { 'changes' : changes } )

    def reloadProfiles( self, msg = None ):
        newProfiles = []
        for row in self.db.execute( self.loadProfiles.bind( tuple() ) ):
            newProfiles.append( TaskingRule( self, row[ 0 ], row[ 1 ], row[ 2 ] ) )

        self.profiles = newProfiles

        self.log( 'reloaded %d profiles' % ( len( newProfiles ), ) )

        return ( True, )
