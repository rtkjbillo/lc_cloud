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
_x_ = Actor.importLib( '../../utils/hcp_helpers', '_x_' )
AgentId = Actor.importLib( '../../utils/hcp_helpers', 'AgentId' )

class StateEvent ( object ):
    __slots__ = [ 'event', 'routing', 'mtd' ]

    def __init__( self, routing, event, mtd ):
        self.event = event
        self.routing = routing
        self.mtd = mtd

    def __repr__( self ):
        return 'Routing( %s )-Event( %s )-Mtd( %s )' % ( self.routing, self.event, self.mtd )

class StateTransition ( object ):
    def __init__( self,
                  toState, 
                  evalFunc,
                  isReportOnMatch = False, 
                  isRecordOnMatch = False, 
                  isKillOnEmptyHistory = False ):
        self.isReportOnMatch = isReportOnMatch
        self.isRecordOnMatch = isRecordOnMatch
        self.isKillOnEmptyHistory = isKillOnEmptyHistory
        self.toState = toState
        self.evalFunc = evalFunc

class State ( object ):
    def __init__( self, *transitions ):
        self.transitions = transitions

class StateMachineDescriptor ( object ):
    def __init__( self, *states, **kwargs ):
        self.states = states
        # Due what seems like a bug in **kwargs passing along with *args in Python
        # (I'm sure there is a reason I can't find), we must validate the arguments
        # from the dict with default values instead of through default-value params.
        self._isWindows = kwargs.get( 'isForWindows', True )
        self._isMac = kwargs.get( 'isForMac', True )
        self._isLinux = kwargs.get( 'isForLinux', True )
        self._debugFunc = None

    def setDebugFunc( self, func ):
        self._debugFunc = func
        self._debugLog( "Debuggning enabled" )

    def _debugLog( self, msg ):
        if self._debugFunc is None: return
        self._debugFunc( ':= %s' % ( msg, ) )

    def _debugLogTransition( self, currentState, transitionIndex, transition, isSuccess ):
        if self._debugFunc is None: return
        flags = ''
        if transition.isRecordOnMatch:
            flags += 'R'
        if transition.isRecordOnMatch:
            flags += 'P'
        if transition.isKillOnEmptyHistory:
            flags += 'K'
        self._debugLog( '@%s %s->%s ===> %s ( %s )' % ( currentState, transitionIndex, transition.toState, isSuccess, flags ) )

class _StateMachineContext( object ):
    __slots__ = [ '_descriptor', '_currentState', '_history', '_indexes' ]

    def __init__( self, descriptor ):
        self._descriptor = descriptor
        self._currentState = 0
        self._history = []
        self._indexes = self._defaultIndexes()

    @classmethod
    def _defaultIndexes( cls ):
        return { 'atom' : {}, 'pid' : {}, 'ts' : {}, 'max_ts' : 0 }

    def saveState( self ):
        return {
            'current_state' : self._currentState,
            'history' : self._history,
        }

    def restoreState( self, savedState ):
        self._currentState = savedState[ 'current_state' ]
        for evt in savedState[ 'history' ]:
            self.addToHistory( evt )

    def addToHistory( self, evt ):
        self._history.append( evt )
        self._indexes[ 'atom' ][ _x_( evt.event, '?/hbs.THIS_ATOM' ) ] = evt
        self._indexes[ 'pid' ][ _x_( evt.event, '?/base.PROCESS_ID' ) ] = evt
        thisTs = evt.event.get( 'base.TIMESTAMP', 0 )
        self._indexes[ 'ts' ][ thisTs ] = evt
        if thisTs > self._indexes[ 'max_ts' ]:
            self._indexes[ 'max_ts' ] = thisTs

    def update( self, event ):
        reportContent = None
        isStayAlive = True
        state = self._descriptor.states[ self._currentState ]
        i = 0
        for transition in state.transitions:
            if transition.evalFunc( event, self._history, self._indexes ):
                self._descriptor._debugLogTransition( self._currentState, i, transition, True )
                if transition.isRecordOnMatch:
                    self.addToHistory( event )
                if transition.isReportOnMatch:
                    reportContent = self._history
                    self._descriptor._debugLog( 'Reporting ( C: %s )' % ( [ x.routing for x in reportContent ] ) )
                if ( 0 == transition.toState or 
                     ( transition.isKillOnEmptyHistory and 0 == len( self._history ) ) ):
                    isStayAlive = False
                self._currentState = transition.toState
                break
            self._descriptor._debugLogTransition( self._currentState, i, transition, False )
            i += 1

        return ( reportContent, isStayAlive )


class StateMachine ( object ):
    def __init__( self, descriptor ):
        self._descriptor = descriptor

    def prime( self, newEvent ):
        aid = AgentId( newEvent.routing[ 'aid' ] )
        if aid.isWindows():
            if not self._descriptor._isWindows:
                return None
        elif aid.isMacOSX():
            if not self._descriptor._isMac:
                return None
        elif aid.isLinux():
            if not self._descriptor._isLinux:
                return None
        newMachine = None
        state = self._descriptor.states[ 0 ]
        i = 0
        for transition in state.transitions:
            if 0 != transition.toState and transition.evalFunc( newEvent, [], _StateMachineContext._defaultIndexes() ):
                self._descriptor._debugLogTransition( '-', i, transition, True )
                newMachine = _StateMachineContext( self._descriptor )
                newMachine.update( newEvent )
                break
            self._descriptor._debugLogTransition( '-', i, transition, False )
            i += 1

        return newMachine

