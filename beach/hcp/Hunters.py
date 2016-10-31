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
CreateOnAccess = Actor.importLib( 'utils/hcp_helpers', 'CreateOnAccess' )
Event = Actor.importLib( 'utils/hcp_helpers', 'Event' )
InvestigationNature = Actor.importLib( 'utils/hcp_helpers', 'InvestigationNature' )
InvestigationConclusion = Actor.importLib( 'utils/hcp_helpers', 'InvestigationConclusion' )
_x_ = Actor.importLib( 'utils/hcp_helpers', '_x_' )

import time
import uuid
import traceback

class _TaskResp ( object ):
    def __init__( self, trxId, inv ):
        self._trxId = trxId
        self._inv = inv
        self.wasReceived = False
        self.responses = []
        self._event = Event()
    
    def _add( self, newData ):
        if 'hbs.CLOUD_NOTIFICATION' == newData.keys()[ 0 ]:
            self.wasReceived = True
        else:
            self.responses.append( newData )
            self._event.set()
    
    def wait( self, timeout ):
        return self._event.wait( timeout )

    def done( self ):
        self._inv.actor.unhandle( self._trxId )
        self._inv.liveTrx.remove( self._trxId )

class _Investigation ( object ):
    def __init__( self, actorRef, detect, invId = None ):
        self.actor = actorRef
        self.invId = invId
        self.taskId = 0
        self.liveTrx = []
        if invId is None:
            invId = '%s/%s' % ( self.actor.__class__.__name__, str( uuid.uuid4() ) )
        if not self.actor._registerToInvData( self.invId ):
            raise Exception( 'could not register investigation' )
        resp = self.actor._reporting.request( 'new_inv', 
                                              { 'inv_id' : self.invId, 
                                                'detect' : detect,
                                                'ts' : time.time(),
                                                'hunter' : self.actor._hunterName } )
        if not resp.isSuccess:
            raise Exception( 'could not create investigation' )
        self.conclude( 'Hunter %s starting investigation.' % self.actor.__class__.__name__,
                       InvestigationNature.OPEN, 
                       InvestigationConclusion.RUNNING )

    def close( self ):
        self.actor._unregisterToInvData( self.invId )
        for trx in self.liveTrx:
            self.actor.unhandle( trx )
        resp = self.actor._reporting.request( 'close_inv', 
                                              { 'inv_id' : self.invId,
                                                'ts' : time.time(),
                                                'hunter' : self.actor._hunterName } )
        if not resp.isSuccess:
            raise Exception( 'error closing investigation' )

    def task( self, why, dest, cmdsAndArgs, isNeedResp = True ):
        ret = None
        if type( cmdsAndArgs[ 0 ] ) not in ( tuple, list ):
            cmdsAndArgs = ( cmdsAndArgs, )
        data = { 'dest' : dest, 'tasks' : cmdsAndArgs }

        # Currently Hunters only operate live
        data[ 'expiry' ] = 0
        trxId = '%s//%s' % ( self.invId, self.taskId )
        data[ 'inv_id' ] = trxId

        self.taskId += 1

        resp = self.actor._tasking.request( 'task', data, key = dest, timeout = 60, nRetries = 0 )
        if resp.isSuccess:
            self.actor.log( "sent for tasking: %s" % ( str(cmdsAndArgs), ) )

            if isNeedResp:
                ret = _TaskResp( trxId, self )

                def _syncRecv( msg ):
                    routing, event, mtd = msg.data
                    ret._add( event )
                    return ( True, )

                self.actor.handle( trxId, _syncRecv )
                self.liveTrx.append( trxId )
        else:
            self.actor.log( "failed to send tasking" )

        taskInfo = { 'inv_id' : self.invId,
                     'ts' : time.time(),
                     'task' : cmdsAndArgs,
                     'why' : why,
                     'dest' : dest,
                     'is_sent' : resp.isSuccess,
                     'hunter' : self.actor._hunterName }
        if not resp.isSuccess:
            taskInfo[ 'error' ] = resp.error

        resp = self.actor._reporting.request( 'inv_task', taskInfo )
        if not resp.isSuccess:
            raise Exception( 'could not record tasking' )

        return ret

    def reportData( self, why, data = {} ):
        if type( data ) not in ( list, tuple, dict ):
            raise Exception( 'reported data must be json' )
        resp = self.actor._reporting.request( 'report_inv', 
                                              { 'inv_id' : self.invId,
                                                'ts' : time.time(),
                                                'data' : data,
                                                'why' : why,
                                                'hunter' : self.actor._hunterName } )
        if not resp.isSuccess:
            raise Exception( 'error recording inv data' )

    def conclude( self, why, inv_nature, inv_conclusion ):
        resp = self.actor._reporting.request( 'conclude_inv', 
                                              { 'inv_id' : self.invId,
                                                'ts' : time.time(),
                                                'why' : why,
                                                'nature' : inv_nature,
                                                'conclusion' : inv_conclusion,
                                                'hunter' : self.actor._hunterName } )
        if not resp.isSuccess:
            raise Exception( 'error recording inv conclusion' )

    def isDuplicate( self, invKey, ttl ):
        resp = self.actor.Models.request( 'get_kv', { 'cat' : 'inv_dupe', 'k' : invKey } )
        if resp.isSuccess:
            return resp.data[ 'v' ]
        self.actor.Models.shoot( 'set_kv', { 'cat' : 'inv_dupe', 'k' : invKey, 'v' : self.invId, 'ttl' : ttl } )
        return False

class Hunter ( Actor ):
    def init( self, parameters ):
        self._hunterName = self.__class__.__name__
        if not hasattr( self, 'investigate' ):
            raise Exception( 'Hunt requires an investigate( investigation, detect ) callback' )
        self._registration = self.getActorHandle( 'analytics/huntsmanager' )
        if hasattr( self, 'detects' ):
            for detect in self.detects:
                self._registerToDetect( detect )

        self.handle( 'detect', self._handleDetects )

        self._contexts = {}

        self._reporting = CreateOnAccess( self.getActorHandle, 'analytics/reporting' )
        self._tasking = CreateOnAccess( self.getActorHandle, 'analytics/autotasking', mode = 'affinity' )

        # APIs made available for Hunts
        self.Models = CreateOnAccess( self.getActorHandle, 'models' )
        self.VirusTotal = CreateOnAccess( self.getActorHandle, 'analytics/virustotal' )
        self.Alexa = CreateOnAccess( self.getActorHandle, 'analytics/alexadns' )

    def _registerToDetect( self, detect ):
        resp = self._registration.request( 'reg_detect', { 'uid' : self.name, 'name' : detect, 'hunter_type' : self._hunterName } )
        return resp.isSuccess

    def _registerToInvData( self, inv_id ):
        resp = self._registration.request( 'reg_inv', { 'uid' : self.name, 'name' : inv_id } )
        return resp.isSuccess

    def _unregisterToDetect( self, detect ):
        resp = self._registration.request( 'unreg_detect', { 'uid' : self.name, 'name' : detect, 'hunter_type' : self._hunterName } )
        return resp.isSuccess

    def _unregisterToInvData( self, inv_id ):
        resp = self._registration.request( 'unreg_inv', { 'uid' : self.name, 'name' : inv_id } )
        self._contexts[ inv_id ][ 1 ].acquire()
        del( self._contexts[ inv_id ] )
        return resp.isSuccess

    def _handleDetects( self, msg ):
        detect = msg.data
        self.delay( 0, self.createInvestigation, inv_id = detect[ 'detect_id' ], detect = detect )
        return ( True, )

    def createInvestigation( self, inv_id = None, detect = {} ):
        try:
            inv = _Investigation( self, detect, invId = inv_id )
            self.investigate( inv, detect )
        except:
            self.logCritical( traceback.format_exc() )
        finally:
            inv.close()

    #==========================================================================
    #   Model Helpers
    #==========================================================================    
    def getSingleAtom( self, id ):
        resp = self.Models.request( 'get_atoms_from_root', { 'id' : id, 'depth' : 0 } )
        if resp.isSuccess and 0 < len( resp.data ):
            return resp.data[ 0 ]
        else:
            return None

    def getChildrenAtoms( self, id, depth = 5 ):
        resp = self.Models.request( 'get_atoms_from_root', { 'id' : id, 'depth' : depth } )
        if resp.isSuccess:
            return resp.data
        else:
            return None

    # This is a generator
    def crawlUpParentTree( self, rootEvent, rootAtom = None ):
        currentEvent = rootEvent
        while True:
            if currentEvent is None and rootAtom is not None:
                parentAtom = rootAtom
            else:
                parentAtom = _x_( currentEvent, '?/hbs.PARENT_ATOM' )
            if parentAtom is None:
                return
            parentEvent = self.getSingleAtom( parentAtom )
            if parentEvent is None:
                return
            currentEvent = parentEvent
            yield parentEvent

    def getObjectInfo( self, objName, objType ):
        resp = self.Models.request( 'get_obj_view', { 'obj_name' : objName, 'obj_type' : objType } )
        if resp.isSuccess:
            return resp.data
        else:
            return None

    def getLastNSecondsOfEventsFrom( self, lastNSeconds, host, ofTypes = None ):
        resp = self.Models.request( 'get_timeline', 
                                    { 'id' : host, 
                                      'types' : ofTypes, 
                                      'after' : int( time.time() ) - lastNSeconds,
                                      'is_include_content' : True } )
        if resp.isSuccess:
            return [ x[ 3 ] for x in resp.data[ 'events' ] if x[ 3 ] is not None ]
        else:
            return []

    def getVTReport( self, fileHash ):
        report = None
        mdReport = []
        resp = self.VirusTotal.request( 'get_report', { 'hash' : fileHash } )
        if resp.isSuccess:
            report = resp.data[ 'report' ]
            for av, res in report.items():
                if res is None:
                    del( report[ av ] )

        if report is not None and 0 < len( report ):
            mdReport = [ '| AV | Result |',
                         '| -- | ------ |' ]
            for av, res in report.iteritems():
                mdReport.append( '| %s | %s |' % ( av, res ) )
        
        return ( report, '\n'.join( mdReport ) )

    def listToMdTable( self, headers, l ):
        table = [ '| %s |' % ( ' | '.join( headers ) ) ]
        table.append( '|%s' % ( ' - |' * len( headers ) ) )
        for row in l:
            table.append( '| %s |' % ( ' | '.join( row ) ) )
        return '\n'.join( table )

    def isAlexaDomain( self, domain ):
        isAlexa = False
        resp = self.Alexa.request( 'is_in_top', { 'domain' : domain } )
        if resp.isSuccess:
            if resp.data[ 'n' ] is not None:
                isAlexa = True
        return isAlexa