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
CreateOnAccess = Actor.importLib( 'hcp_helpers', 'CreateOnAccess' )

import time
import uuid

class Hunt ( Actor ):
    def init( self, parameters ):
        if not hasattr( self, 'updateHunt' ):
            raise Exception( 'Hunt requires an updateHunt( context, newEvent ) callback' )
        self._ttl = parameters.get( 'ttl', 60 * 60 * 24 )
        self._registration = self.getActorHandle( 'analytics/huntsmanager' )
        self._regInvTtl = {}
        if hasattr( self, 'detects' ):
            for detect in self.detects:
                self._registerToDetect( detect )

        self.handle( 'detect', self._handleDetects )
        self.handle( 'inv', self._handleInvData )

        self._contexts = {}

        self._reporting = CreateOnAccess( self.getActorHandle, 'analytics/report' )
        self._tasking = CreateOnAccess( self.getActorHandle, 'analytics/autotasking', mode = 'affinity' )

        # APIs made available for Hunts
        self.Models = CreateOnAccess( self.getActorHandle, 'models' )
        self.VirusTotal = CreateOnAccess( self.getActorHandle, 'analytics/virustotal' )

    def _regCulling( self ):
        curTime = int( time.time() )
        for name in ( name for name, ts in self._regInvTtl.iteritems() if ts < ( curTime - self._ttl ) ):
            self._unregisterToInvData( name )

    def _registerToDetect( self, detect ):
        resp = self._registration.request( 'reg_detect', { 'uid' : self.name, 'name' : detect } )
        return resp.isSuccess

    def _registerToInvData( self, inv_id ):
        resp = self._registration.request( 'reg_inv', { 'uid' : self.name, 'name' : inv_id } )
        self._regInvTtl[ inv_id ] = int( time.time() )
        return resp.isSuccess

    def _unregisterToDetect( self, detect ):
        resp = self._registration.request( 'unreg_detect', { 'uid' : self.name, 'name' : detect } )
        return resp.isSuccess

    def _unregisterToInvData( self, inv_id ):
        resp = self._registration.request( 'unreg_inv', { 'uid' : self.name, 'name' : inv_id } )
        del( self._regInvTtl[ inv_id ] )
        del( self._contexts[ inv_id ] )
        return resp.isSuccess

    def generateNewInv( self ):
        inv_id = '%s/%s' % ( self.__class__.__name__, str( uuid.uuid4() ) )
        isSuccess = self._registerToInvData( inv_id )
        self._handleDetects( { 'report_id' : inv_id, 'detect' : {} } )
        return isSuccess

    def postUpdatedDetect( self, context ):
        self.log( 'updating report %s with new context' % context[ 'report_id' ] )
        self._reporting.shoot( 'report', context )

    def _handleDetects( self, msg ):
        detect = msg.data
        if detect[ 'report_id' ] not in self._contexts:
            inv_id = detect[ 'report_id' ]
            self._registerToInvData( inv_id )
            self._contexts[ inv_id ] = detect
            isKeepSubscribing = self.updateHunt( detect, None )
            if not isKeepSubscribing:
                self._unregisterToInvData( inv_id )
                self.log( 'investigation requested termination' )

    def _handleInvData( self, msg ):
        routing, event, mtd = msg.data
        inv_id = routing[ 'investigation_id' ]
        if inv_id in self._contexts:
            self._regInvTtl[ inv_id ] = int( time.time() )
            curContext = self._contexts[ inv_id ]
            isKeepSubscribing = self.updateHunt( curContext, msg.data )
            if not isKeepSubscribing:
                self._unregisterToInvData( inv_id )
                self.log( 'investigation requested termination' )
        else:
            self.logCritical( 'received investigation data without context' )

    def task( self, dest, cmdsAndArgs, expiry = None, inv_id = None ):

        if type( cmdsAndArgs[ 0 ] ) not in ( tuple, list ):
            cmdsAndArgs = ( cmdsAndArgs, )
        data = { 'dest' : dest, 'tasks' : cmdsAndArgs }

        if expiry is not None:
            data[ 'expiry' ] = expiry
        if inv_id is not None:
            data[ 'inv_id' ] = inv_id

        self._tasking.shoot( 'task', data, key = dest )
        self.log( "sent for tasking: %s" % ( str(cmdsAndArgs), ) )
