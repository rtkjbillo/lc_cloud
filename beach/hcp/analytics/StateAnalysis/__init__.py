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

class StateEvent ( object ):
    __slots__ = [ 'event', 'routing', 'mtd' ]

    def __init__( self, routing, event, mtd ):
        self.event = event
        self.routing = routing
        self.mtd = mtd

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
    def __init__( self, priority, summary, detectName, *states ):
        self.states = states
        self.detectName = detectName
        self.priority = priority
        self.summary = summary
        self._debugFunc = None

    def setDebugFunc( self, func ):
        self._debugFunc = func
        self._debugLog( "Debuggning enabled" )

    def _debugLog( self, msg ):
        if self._debugFunc is None: return
        self._debugFunc( '%s := %s' % ( self.detectName, msg ) )

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

    def addToHistory( self, evt ):
        self._history.append( evt )
        self._indexes[ 'atom' ][ _x_( evt.event, '?/hbs.THIS_ATOM' ) ] = evt
        self._indexes[ 'pid' ][ _x_( evt.event, '?/base.PROCESS_ID' ) ] = evt
        thisTs = evt.event.get( 'base.TIMESTAMP', 0 )
        self._indexes[ 'ts' ][ thisTs ] = evt
        if thisTs > self._indexes[ 'max_ts' ]:
            self._indexes[ 'max_ts' ] = thisTs

    def update( self, event ):
        reportPriority = None
        reportSummary = None
        reportType = None
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
                    reportPriority = self._descriptor.priority
                    reportSummary = self._descriptor.summary
                    reportType = self._descriptor.detectName
                    reportContent = self._history
                    self._descriptor._debugLog( 'Reporting ( P: %s, S: %s, T: %s, C: %s )' % ( reportPriority, 
                                                                                               reportSummary, 
                                                                                               reportType, 
                                                                                               [ x.routing for x in reportContent ] ) )
                if ( 0 == transition.toState or 
                     ( transition.isKillOnEmptyHistory and 0 == len( self._history ) ) ):
                    isStayAlive = False
                self._currentState = transition.toState
                break
            self._descriptor._debugLogTransition( self._currentState, i, transition, False )
            i += 1

        return (reportPriority, reportSummary, reportType, reportContent, isStayAlive)


class StateMachine ( object ):
    def __init__( self, descriptor ):
        self._descriptor = descriptor

    def prime( self, newEvent ):
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

