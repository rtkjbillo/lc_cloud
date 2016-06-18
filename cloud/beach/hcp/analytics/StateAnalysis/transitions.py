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
_x_ = Actor.importLib( '../../hcp_helpers', '_x_' )
_xm_ = Actor.importLib( '../../hcp_helpers', '_xm_' )

def NewProcessNamed( regexp ):
    regexp = re.compile( regexp )
    def _processNamed( history, event ):
        newProcName = _x_( event.event, 'notification.NEW_PROCESS/base.FILE_PATH' )
        if newProcName is not None and regexp.match( newProcName ):
            return True
        else:
            return False
    return _processNamed

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
        parentPid = _x_( event.event, 'notification.NEW_PROCESS/base.PARENT_PROCESS_ID' )
        if parentPid is not None:
            if parentPid in ( _x_( x.event, 'notification.NEW_PROCESS/base.PROCESS_ID' ) for x in history ):
                return True
        return False
    return _parentProcessInHistory

def NotParentProcessInHistory():
    f = ParentProcessInHistory()
    def _notParentProcessInHistory( history, event ):
        return not f( history, event )
    return _notParentProcessInHistory

def RunningPidReset():
    def _runningPidReset( history, event ):
        currentPid = _x_( event.event, 'notification.NEW_PROCESS/base.PROCESS_ID' )
        if currentPid is None:
            currentPid = _x_( event.event, 'notification.TERMINATE_PROCESS/base.PROCESS_ID' )
        if currentPid is not None:
            for proc in history:
                tmpPid = _x_( proc.event, '?/base.PROCESS_ID' )
                if tmpPid is not None and tmpPid == currentPid:
                    history.remove( proc )
                    return True

        return False
    return _runningPidReset

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