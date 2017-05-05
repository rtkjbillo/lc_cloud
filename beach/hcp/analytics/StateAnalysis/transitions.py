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
    def _processNamed( history, event ):
        newProcName = _x_( event.event, 'notification.NEW_PROCESS/base.FILE_PATH' )
        if newProcName is None:
            newProcName = _x_( event.event, 'notification.EXISTING_PROCESS/base.FILE_PATH' )
        if newProcName is not None and regexp.match( newProcName ):
            return True
        else:
            return False
    return _processNamed

def NewProcessWithPrivilege( isRoot ):
    def _processWithPriv( history, event ):
        newProcUid = _x_( event.event, 'notification.NEW_PROCESS/base.USER_ID' )
        if newProcUid is None:
            newProcUid = _x_( event.event, 'notification.EXISTING_PROCESS/base.USER_ID' )
        if newProcUid is not None and ( ( isRoot and 0 == newProcUid ) or ( not isRoot and 0 != newProcUid ) ):
            return True
        else:
            return False
    return _processWithPriv

def NewDocumentNamed( regexp ):
    try:
        regexp.match( '' )
    except:
        regexp = re.compile( regexp )
    def _docNamed( history, event ):
        newDocName = _x_( event.event, 'notification.NEW_DOCUMENT/base.FILE_PATH' )
        if newDocName is not None and regexp.match( newDocName ):
            return True
        else:
            return False
    return _docNamed

def HistoryOlderThan( nMilliseconds ):
    def _historyOlderThan( history, event ):
        newTs = event.event.get( 'base.TIMESTAMP', 0 )
        newest = max( x.event.get( 'base.TIMESTAMP', 0 ) for x in history )
        if newTs > newest + nMilliseconds:
            return True
        else:
            return False

    return _historyOlderThan

def ParentProcessInHistory():
    def _parentProcessInHistory( history, event ):
        parentPid = _x_( event.event, '?/hbs.PARENT_ATOM' )
        if parentPid is not None:
            if parentPid in ( _x_( x.event, 'notification.NEW_PROCESS/hbs.THIS_ATOM' ) for x in history ):
                return True
            if parentPid in ( _x_( x.event, 'notification.EXISTING_PROCESS/hbs.THIS_ATOM' ) for x in history ):
                return True
        return False
    return _parentProcessInHistory

def RunningPidReset():
    def _runningPidReset( history, event ):
        currentPid = _x_( event.event, 'notification.NEW_PROCESS/base.PROCESS_ID' )
        if currentPid is None:
            currentPid = _x_( event.event, 'notification.TERMINATE_PROCESS/base.PROCESS_ID' )
            if currentPid is None:
                currentPid = _x_( event.event, 'notification.EXISTING_PROCESS/base.PROCESS_ID' )
        if currentPid is not None:
            for proc in history:
                tmpPid = _x_( proc.event, '?/base.PROCESS_ID' )
                if tmpPid is not None and tmpPid == currentPid:
                    history.remove( proc )
                    return True

        return False
    return _runningPidReset

def SensorRestart():
    def _sensorRestart( history, event ):
        if( 'notification.STARTING_UP' == event.routing[ 'event_type' ] or
            'notification.SHUTTING_DOWN' == event.routing[ 'event_type' ] ):
            return True
        return False
    return _sensorRestart

def AlwaysReturn( bValue ):
    def _alwaysReturn( history, event ):
        return bValue
    return _alwaysReturn

def EventOfType( eventType ):
    def _eventOfType( history, event ):
        if eventType == event.routing.get( 'event_type', '' ):
            return True
        else:
            return False
    return _eventOfType

def InverseTransition( transition ):
    def _notTransition( history, event ):
        return not transition( history, event )
    return _notTransition

def AndTransitions( *transitions ):
    def _andTransition( history, event ):
        return all( tr( history, event ) for tr in transitions )
    return _andTransition

def OrTransitions( *transitions ):
    def _orTransition( history, event ):
        return any( tr( history, event ) for tr in transitions )
    return _orTransition
