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
NotParentProcessInHistory = Actor.importLib( './transitions', 'NotParentProcessInHistory' )

def ProcessBurst( name, procRegExp, nPerBurst, withinSeconds ):
    states = []
    for i in xrange( 0, nPerBurst ):
        states.append( State( StateTransition( isRecordOnMatch = True, 
                                               isReportOnMatch = False if i < nPerBurst - 1 else True,
                                               toState = i + 1 if i < nPerBurst - 1 else 0, 
                                               evalFunc = NewProcessNamed( procRegExp ) ), 
                              StateTransition( toState = 0, 
                                               evalFunc = HistoryOlderThan( withinSeconds ) ) ) )
    return StateMachineDescriptor( name, *states )

def ProcessDescendant( name, parentRegExp, childRegExp, isDirectOnly ):
    parentState = State( StateTransition( isRecordOnMatch = True,
                                          toState = 1,
                                          evalFunc = NewProcessNamed( parentRegExp ) ) )
    descendantState = State( StateTransition( toState = 1,
                                              isKillOnEmptyHistory = True,
                                              evalFunc = RunningPidReset() ),
                             StateTransition( toState = 1,
                                              evalFunc = NotParentProcessInHistory() ),
                             # Anything below is point is a descendant since the previous 
                             # transition matches on non-descendants.
                             StateTransition( isRecordOnMatch = True,
                                              isReportOnMatch = True,
                                              toState = 0,
                                              evalFunc = NewProcessNamed( childRegExp ) ),
                             StateTransition( isRecordOnMatch = True,
                                              toState = 1,
                                              evalFunc = AlwaysReturn( not isDirectOnly ) ) )

    return StateMachineDescriptor( name, parentState, descendantState )

def EventBurst( name, eventType, nPerBurst, withinSeconds ):
    states = []
    for i in xrange( 1, nPerBurst ):
        states.append( State( StateTransition( isRecordOnMatch = True, 
                                               isReportOnMatch = False if i < nPerBurst else True,
                                               toState = i if i < nPerBurst else 0, 
                                                 evalFunc = EventOfType( eventType ) ), 
                              StateTransition( toState = 0, 
                                                  evalFunc = HistoryOlderThan( withinSeconds ) ) ) )
    return StateMachineDescriptor( name, *states )