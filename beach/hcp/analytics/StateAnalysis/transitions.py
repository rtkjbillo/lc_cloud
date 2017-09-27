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
import re
_x_ = Actor.importLib( '../../utils/hcp_helpers', '_x_' )
_xm_ = Actor.importLib( '../../utils/hcp_helpers', '_xm_' )

def NewProcessNamed( regexp ):
    try:
        regexp.match( '' )
    except:
        regexp = re.compile( regexp )
    def _processNamed( event, history, indexes ):
        newProcName = _x_( event.event, 'notification.NEW_PROCESS/base.FILE_PATH' )
        if newProcName is None:
            newProcName = _x_( event.event, 'notification.EXISTING_PROCESS/base.FILE_PATH' )
        if newProcName is not None and regexp.match( newProcName ):
            return True
        else:
            return False
    return _processNamed

def NewProcessWithPrivilege( isRoot ):
    def _processWithPriv( event, history, indexes ):
        newProcUid = _x_( event.event, 'notification.NEW_PROCESS/base.USER_ID' )
        if newProcUid is None:
            newProcUid = _x_( event.event, 'notification.EXISTING_PROCESS/base.USER_ID' )
        if newProcUid is not None and ( ( isRoot and 0 == newProcUid ) or ( not isRoot and 0 != newProcUid ) ):
            return True
        else:
            return False
    return _processWithPriv

def NewProcessWithUser( regexp ):
    try:
        regexp.match( '' )
    except:
        regexp = re.compile( regexp )
    def _processWithUser( event, history, indexes ):
        newProcAccount = _x_( event.event, 'notification.NEW_PROCESS/base.USER_NAME' )
        if newProcAccount is None:
            newProcAccount = _x_( event.event, 'notification.EXISTING_PROCESS/base.USER_NAME' )
        if newProcAccount is not None and regexp.match( newProcAccount ):
            return True
        else:
            return False
    return _processWithUser

def NewDocumentNamed( regexp ):
    try:
        regexp.match( '' )
    except:
        regexp = re.compile( regexp )
    def _docNamed( event, history, indexes ):
        newDocName = _x_( event.event, 'notification.NEW_DOCUMENT/base.FILE_PATH' )
        if newDocName is not None and regexp.match( newDocName ):
            return True
        else:
            return False
    return _docNamed

def HistoryOlderThan( nMilliseconds ):
    def _historyOlderThan( event, history, indexes ):
        newTs = event.event.get( 'base.TIMESTAMP', 0 )
        newest = indexes[ 'max_ts' ]
        if newTs > newest + nMilliseconds:
            return True
        else:
            return False

    return _historyOlderThan

def ParentProcessInHistory():
    def _parentProcessInHistory( event, history, indexes ):
        parentPid = _x_( event.event, '?/hbs.PARENT_ATOM' )
        if parentPid is not None:
            parent = indexes[ 'atom' ].get( parentPid, None )
            if parent is not None and '_PROCESS' in parent.routing.get( 'event_type', '' ):
                return True
        return False
    return _parentProcessInHistory

def RunningPidReset():
    def _runningPidReset( event, history, indexes ):
        currentPid = _x_( event.event, 'notification.NEW_PROCESS/base.PROCESS_ID' )
        if currentPid is None:
            currentPid = _x_( event.event, 'notification.TERMINATE_PROCESS/base.PROCESS_ID' )
            if currentPid is None:
                currentPid = _x_( event.event, 'notification.EXISTING_PROCESS/base.PROCESS_ID' )
        if currentPid is not None:
            proc = indexes[ 'pid' ].get( currentPid, None )
            if proc is not None:
                for idx in indexes.itervalues():
                    if type( idx ) is dict:
                        delIdx = None
                        for idxKey, idxVal in idx.iteritems():
                            if idxVal == proc:
                                delIdx = idxKey
                                break
                        if delIdx is not None: del( idx[ delIdx ] )
                history.remove( proc )
                return True

        return False
    return _runningPidReset

def SensorRestart():
    def _sensorRestart( event, history, indexes ):
        if( 'notification.STARTING_UP' == event.routing[ 'event_type' ] or
            'notification.SHUTTING_DOWN' == event.routing[ 'event_type' ] ):
            return True
        return False
    return _sensorRestart

def AlwaysReturn( bValue ):
    def _alwaysReturn( event, history, indexes ):
        return bValue
    return _alwaysReturn

def EventOfType( eventType ):
    def _eventOfType( event, history, indexes ):
        if eventType == event.routing.get( 'event_type', '' ):
            return True
        else:
            return False
    return _eventOfType

def InverseTransition( transition ):
    def _notTransition( event, history, indexes ):
        return not transition( event, history, indexes )
    return _notTransition

def AndTransitions( *transitions ):
    def _andTransition( event, history, indexes ):
        return all( tr( event, history, indexes ) for tr in transitions )
    return _andTransition

def OrTransitions( *transitions ):
    def _orTransition( event, history, indexes ):
        return any( tr( event, history, indexes ) for tr in transitions )
    return _orTransition
