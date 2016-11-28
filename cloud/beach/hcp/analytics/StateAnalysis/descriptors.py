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
StateMachineDescriptor = Actor.importLib( './', 'StateMachineDescriptor' )
State = Actor.importLib( './', 'State' )
StateTransition = Actor.importLib( './', 'StateTransition' )
NewProcessNamed = Actor.importLib( './transitions', 'NewProcessNamed' )
HistoryOlderThan = Actor.importLib( './transitions', 'HistoryOlderThan' )
RunningPidReset = Actor.importLib( './transitions', 'RunningPidReset' )
AlwaysReturn = Actor.importLib( './transitions', 'AlwaysReturn' )
EventOfType = Actor.importLib( './transitions', 'EventOfType' )
ParentProcessInHistory = Actor.importLib( './transitions', 'ParentProcessInHistory' )
InverseTransition = Actor.importLib( './transitions', 'InverseTransition' )
SensorRestart = Actor.importLib( './transitions', 'SensorRestart' )
AndTransitions = Actor.importLib( './transitions', 'AndTransitions' )
OrTransitions = Actor.importLib( './transitions', 'OrTransitions' )
NewDocumentNamed = Actor.importLib( './transitions', 'NewDocumentNamed' )

def ProcessBurst( name, priority, summary, procRegExp, nPerBurst, withinMilliSeconds ):
    states = []
    for i in xrange( 0, nPerBurst ):
        states.append( State( StateTransition( isRecordOnMatch = True, 
                                               isReportOnMatch = False if i < nPerBurst - 1 else True,
                                               toState = i + 1 if i < nPerBurst - 1 else 0, 
                                               evalFunc = NewProcessNamed( procRegExp ) ), 
                              StateTransition( toState = 0, 
                                               evalFunc = HistoryOlderThan( withinMilliSeconds ) ) ) )
    return StateMachineDescriptor( priority, summary, name, *states )

def ProcessDescendant( name, priority, summary, parentRegExp, isDirectOnly, childRegExp = None, documentRegExp = None ):
    if childRegExp is not None:
        targetTransition = StateTransition( isRecordOnMatch = True,
                                            isReportOnMatch = True,
                                            toState = 0,
                                            evalFunc = NewProcessNamed( childRegExp ) )
    elif documentRegExp is not None:
        targetTransition = StateTransition( isRecordOnMatch = True,
                                            isReportOnMatch = True,
                                            toState = 0,
                                            evalFunc = NewDocumentNamed( documentRegExp ) )
    else:
        raise Exception( 'no target events for process descendants' )

    parentState = State( StateTransition( isRecordOnMatch = True,
                                          toState = 1,
                                          evalFunc = NewProcessNamed( parentRegExp ) ) )
    descendantState = State( StateTransition( toState = 0,
                                              evalFunc = SensorRestart() ),
                             StateTransition( toState = 1,
                                              isKillOnEmptyHistory = True,
                                              evalFunc = RunningPidReset() ),
                             StateTransition( toState = 1,
                                              evalFunc = InverseTransition( ParentProcessInHistory() ) ),
                             # Anything below is point is a descendant since the previous 
                             # transition matches on non-descendants.
                             targetTransition,
                             StateTransition( isRecordOnMatch = True,
                                              toState = 1,
                                              evalFunc = AndTransitions( EventOfType( 'notification.NEW_PROCESS' ), 
                                                                         AlwaysReturn( not isDirectOnly ) ) ) )

    return StateMachineDescriptor( priority, summary, name, parentState, descendantState )

def EventBurst( name, priority, summary, eventType, nPerBurst, withinMilliSeconds ):
    states = []
    for i in xrange( 0, nPerBurst ):
        states.append( State( StateTransition( isRecordOnMatch = True, 
                                               isReportOnMatch = False if i < nPerBurst else True,
                                               toState = i + 1 if i < nPerBurst - 1 else 0, 
                                               evalFunc = EventOfType( eventType ) ), 
                              StateTransition( toState = 0, 
                                               evalFunc = HistoryOlderThan( withinMilliSeconds ) ) ) )
    return StateMachineDescriptor( priority, summary, name, *states )