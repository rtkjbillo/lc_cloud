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

import time
import uuid

class Hunt ( Actor ):
    def init( self, parameters ):
        if not hasattr( self, 'updateHunt' ):
            raise Exception( 'Hunt requires an updateHunt( context, newEvent ) callback' )
        self._ttl = parameters.get( 'ttl', 60 * 60 * 24 )
        self._registration = self.getActorHandle( 'analytics/huntsmanager' )
        self._regDetectTtl = {}
        self._regInvTtl = {}
        if hasattr( self, 'detects' ):
            for detect in self.detects:
                self.registerToDetect( detect )

        self.handle( 'detect', self._handleDetects )
        self.handle( 'inv', self._handleInvData )

        self._contexts = {}

        self._reporting = self.getActorHandle( 'analytics/report' )
        self._tasking = None
        self.Models = self.getActorHandle( 'models' )

    def _regCulling( self ):
        curTime = int( time.time() )
        for name in ( name for name, ts in self._regDetectTtl.iteritems() if ts < ( curTime - self._ttl ) ):
            self._registration.request( 'unreg_detect', { 'uid' : self.name, 'name' : name } )
        for name in ( name for name, ts in self._regInvTtl.iteritems() if ts < ( curTime - self._ttl ) ):
            self._registration.request( 'unreg_inv', { 'uid' : self.name, 'name' : name } )

    def registerToDetect( self, detect ):
        resp = self._registration.request( 'reg_detect', { 'uid' : self.name, 'name' : detect } )
        self._regDetectTtl[ detect ] = int( time.time() )
        return resp.isSuccess

    def registerToInvData( self, inv_id ):
        resp = self._registration.request( 'reg_inv', { 'uid' : self.name, 'name' : inv_id } )
        self._regInvTtl[ inv_id ] = int( time.time() )
        return resp.isSuccess

    def generateNewInv( self ):
        inv_id = '%s/%s' % ( self.__class__.__name__, str( uuid.uuid4() ) )
        isSuccess = self.registerToInvData( inv_id )
        self._handleDetects( { 'report_id' : inv_id } )
        return isSuccess

    def postUpdatedDetect( self, context ):
        self._reporting.shoot( 'report', context )

    def _handleDetects( self, msg ):
        detect = msg.data
        if detect[ 'report_id' ] not in self._contexts:
            self._contexts[ detect[ 'report_id' ] ] = detect
            self.updateHunt( detect, None )

    def _handleInvData( self, msg ):
        routing, event, mtd = msg.data
        inv_id = routing[ 'investigation_id' ]
        if inv_id in self._contexts:
            curContext = self._contexts[ inv_id ]
            self.updateHunt( curContext, msg.data )

    def task( self, dest, cmdsAndArgs, expiry = None, inv_id = None ):
        if self._tasking is None:
            self._tasking = self.getActorHandle( 'analytics/autotasking', mode = 'affinity' )
            self.log( "creating tasking handle for the first time for this detection module" )

        if type( cmdsAndArgs[ 0 ] ) not in ( tuple, list ):
            cmdsAndArgs = ( cmdsAndArgs, )
        data = { 'dest' : dest, 'tasks' : cmdsAndArgs }

        if expiry is not None:
            data[ 'expiry' ] = expiry
        if inv_id is not None:
            data[ 'inv_id' ] = inv_id

        self._tasking.shoot( 'task', data, key = dest )
        self.log( "sent for tasking: %s" % ( str(cmdsAndArgs), ) )
