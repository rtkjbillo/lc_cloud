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
_x_ = Actor.importLib( '../../hcp_helpers', '_x_' )
_xm_ = Actor.importLib( '../../hcp_helpers', '_xm_' )
SAMState = Actor.importLib( '.', 'SAMState' )
SAMInvalidStructureException = Actor.importLib( '.', 'SAMInvalidStructureException' )
SAMGcStrategy = Actor.importLib( '.', 'SAMGcStrategy' )
SAMSelector = Actor.importLib( 'GenericWidgets', 'SAMSelector' )

class SAMShortTimeProcessGc( SAMGcStrategy ):
    def __init__( self, *a, **k ):
        SAMGcStrategy.__init__( self, *a, **k )
        self.latest = 0

    def collect_pre_all( self, feed, states, newEvent ):
        tmpTime = _x_( newEvent, self.widget.TIMESTAMP_PATH )
        self.latest = tmpTime if tmpTime > self.latest else self.latest

        eventType = newEvent[ 'routing' ][ 'event_type' ]

        if ( eventType == 'notification.STARTING_UP' or
             eventType == 'notification.SHUTTING_DOWN' ):
            del states[:]
            self.widget.log( 'sensor restarted, resetting states' )

    def collect_pre( self, feed, states ):
        for state in states:
            for event in state:
                if _x_( event, self.widget.TIMESTAMP_PATH ) < self.latest - 60:
                    state.remove( event )
                if 0 == len( state ):
                    states.remove( state )
                    self.widget.log( 'garbage collecting a state' )

    def collect_post( self, feed, states ):
        pass

    def collect_post_all( self, feed, states, newEvent ):
        pass

class SAMTimelessProcessGc( SAMGcStrategy ):
    def __init__( self, *a, **k ):
        SAMGcStrategy.__init__( self, *a, **k )
        self.latest = 0

    def collect_pre_all( self, feed, states, newEvent ):
        tmpTime = _x_( newEvent, self.widget.TIMESTAMP_PATH )
        self.latest = tmpTime if tmpTime > self.latest else self.latest

        eventType = newEvent[ 'routing' ][ 'event_type' ]

        if ( eventType == 'notification.STARTING_UP' or
             eventType == 'notification.SHUTTING_DOWN' ):
            del states[:]
            self.widget.log( 'sensor restarted, resetting states' )

    def collect_pre( self, feed, states ):
        pass

    def collect_post( self, feed, states ):
        pass

    def collect_post_all( self, feed, states, newEvent ):
        pass

class SAMProcessDescendants( SAMState ):
    def __init__( self, *a, **k ):
        SAMState.__init__( self, *a, **k )
        self.TIMESTAMP_PATH = 'event/?/base.TIMESTAMP'
        self.PID_PATH = 'event/?/base.PROCESS_ID'
        self.PPID_PATH = 'event/?/base.PARENT_PROCESS_ID'
        self.isDirectDescendantsOnly = self.parameters.get( 'is_direct_only', False )
        self.feedsFrom( '_new',
                        SAMSelector( parameters = { 'event/?/notification.NEW_PROCESS' : None,
                                                    'debug' : self.printDebug } ),
                        SAMShortTimeProcessGc )
        self.feedsFrom( '_end',
                        SAMSelector( parameters = { 'event/?/notification.TERMINATE_PROCESS' : None,
                                                    'debug' : self.printDebug } ),
                        SAMShortTimeProcessGc )

    def feed_parents( self, widget ):
        self.feedsFrom( 'parents', widget, SAMTimelessProcessGc )
        return self

    def feed_descendants( self, widget ):
        self.feedsFrom( 'descendants', widget, SAMShortTimeProcessGc )
        return self

    def execute( self, feedStates ):
        out = []
        if 'parents' not in feedStates or 'descendants' not in feedStates:
            raise SAMInvalidStructureException( 'requires a "parents" and "descendants" feed' )

        revocations = {}

        # Build a revocation list of PID -> TimeRevoked
        # This is for race conditions with asynchronous events and is
        # by no means perfect, but it's better.

        # For New processes
        for state in feedStates[ '_new' ]:
            for nEvent in state:
                nPid = _x_( nEvent, self.PID_PATH )
                for pState in feedStates[ 'parents' ]:
                    for pEvent in pState:
                        if nPid == _x_( pEvent, self.PID_PATH ):
                            revocations[ nPid ] = _x_( nEvent, self.TIMESTAMP_PATH )
        # For Dead processes
        for state in feedStates[ '_end' ]:
            for nEvent in state:
                nPid = _x_( nEvent, self.PID_PATH )
                for pState in feedStates[ 'parents' ]:
                    for pEvent in pState:
                        if nPid == _x_( pEvent, self.PID_PATH ):
                            revocations[ nPid ] = _x_( nEvent, self.TIMESTAMP_PATH )

        # Again horribly ineficient N^2 algorithm but considering the numbers should be quite low
        # we're going with the easy approach for now.
        for cState in feedStates[ 'descendants' ]:
            for cEvent in cState:
                cPPid = _x_( cEvent, self.PPID_PATH )
                for pState in feedStates[ 'parents' ]:
                    for pEvent in pState:
                        pPid = _x_( pEvent, self.PID_PATH )
                        if pPid == cPPid:
                            # Check if it is revoked at that point in time
                            revocationTime = revocations.get( pPid, None )
                            if ( revocationTime is None or
                                 _x_( cEvent, self.TIMESTAMP_PATH ) <= revocationTime ):
                                out.append( [ cEvent ] )
                                if not self.isDirectDescendantsOnly:
                                    feedStates[ 'parents' ].append( [ cEvent ] )

        return out
