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
from beach.beach_api import Beach

from sets import Set

class HuntsManager( Actor ):
    def init( self, parameters, resources ):
        self.beach_api = Beach( parameters[ 'beach_config' ], realm = 'hcp' )
        self.handle( 'reg_detect', self.handleRegDetect )
        self.handle( 'reg_inv', self.handleRegInvestigation )
        self.handle( 'unreg_detect', self.handleRegDetect )
        self.handle( 'unreg_inv', self.handleUnRegInvestigation )

    def deinit( self ):
        pass

    def handleRegDetect( self, msg ):
        uid = msg.data[ 'uid' ]
        name = msg.data[ 'name' ]
        hunter_type = msg.data[ 'hunter_type' ]

        isSuccess = self.beach_api.addToCategory( uid, 'analytics/detects/%s/%s' % ( name, hunter_type ) )
        self.log( 'registering detect %s to %s: %s' % ( uid, name, isSuccess ) )

        return ( isSuccess, )

    def handleUnRegDetect( self, msg ):
        uid = msg.data[ 'uid' ]
        name = msg.data[ 'name' ]
        hunter_type = msg.data[ 'hunter_type' ]

        isSuccess = self.beach_api.removeFromCategory( uid, 'analytics/detects/%s/%s' % ( name, hunter_type ) )
        self.log( 'unregistering detect %s to %s: %s' % ( uid, name, isSuccess ) )

        return ( isSuccess, )

    def handleRegInvestigation( self, msg ):
        uid = msg.data[ 'uid' ]
        name = msg.data[ 'name' ]

        isSuccess = self.beach_api.addToCategory( uid, 'analytics/inv_id/%s' % ( name, ) )
        self.log( 'registering inv %s to %s: %s' % ( uid, name, isSuccess ) )

        return ( isSuccess, )

    def handleUnRegInvestigation( self, msg ):
        uid = msg.data[ 'uid' ]
        name = msg.data[ 'name' ]

        isSuccess = self.beach_api.removeFromCategory( uid, 'analytics/inv_id/%s' % ( name, ) )
        self.log( 'unregistering inv %s to %s: %s' % ( uid, name, isSuccess ) )

        return ( isSuccess, )