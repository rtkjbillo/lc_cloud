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

class StateEvent ( object ):
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

class _StateMachineContext( object ):
    def __init__( self, descriptor ):
        self._descriptor = descriptor
        self._currentState = 0
        self._history = []

    def update( self, event ):
        reportPriority = None
        reportSummary = None
        reportType = None
        reportContent = None
        isStayAlive = True
        state = self._descriptor.states[ self._currentState ]
        for transition in state.transitions:
            if transition.evalFunc( self._history, event ):
                if transition.isRecordOnMatch:
                    self._history.append( event )
                if transition.isReportOnMatch:
                    reportPriority = self._descriptor.priority
                    reportSummary = self._descriptor.summary
                    reportType = self._descriptor.detectName
                    reportContent = self._history
                if ( 0 == transition.toState or 
                     ( transition.isKillOnEmptyHistory and 0 == len( self._history ) ) ):
                    isStayAlive = False
                self._currentState = transition.toState
                break

        return (reportPriority, reportSummary, reportType, reportContent, isStayAlive)


class StateMachine ( object ):
    def __init__( self, descriptor ):
        self._descriptor = descriptor

    def prime( self, newEvent ):
        newMachine = None
        state = self._descriptor.states[ 0 ]
        for transition in state.transitions:
            if 0 != transition.toState and transition.evalFunc( [], newEvent ):
                newMachine = _StateMachineContext( self._descriptor )
                newMachine.update( newEvent )
                break

        return newMachine

