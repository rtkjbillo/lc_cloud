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

class SAMTimeGc( SAMGcStrategy ):
    def __init__( self, *a, **k ):
        SAMGcStrategy.__init__( self, *a, **k )
        self.latest = 0

    def collect_pre_all( self, feed, states, newEvent ):
        tmpTime = _x_( newEvent, self.widget.TIMESTAMP_PATH )
        self.latest = tmpTime if tmpTime > self.latest else self.latest

    def collect_pre( self, feed, states ):
        pass

    def collect_post( self, feed, states ):
        for state in states:
            for event in state:
                ts = _x_( event, self.widget.TIMESTAMP_PATH )
                if ts < self.latest - ( 2 * self.widget.parameters.get( 'within' ) ):
                    state.remove( event )
            if 0 == len( state ):
                states.remove( state )

    def collect_post_all( self, feed, states, newEvent ):
        pass

class SAMTimeCorrelation( SAMState ):
    def __init__( self, *a, **k ):
        SAMState.__init__( self, *a, **k )
        self.TIMESTAMP_PATH = 'event/?/base.TIMESTAMP'

    def feed_from( self, widget ):
        self.feedsFrom( str( widget ), widget, SAMTimeGc )
        return self

    def execute( self, feedStates ):
        if 2 > len( feedStates ):
            raise SAMInvalidStructureException( 'correlation requires at least 2 feeds' )

        within = self.parameters.get( 'within', None )

        if within is None:
            raise SAMInvalidStructureException( 'requires the "within" parameter' )

        def findMatches( curMatches, remainingFeedStates ):
            out = []
            for state in remainingFeedStates[ 0 ]:
                for event in state:
                    ts = _x_( event, self.TIMESTAMP_PATH )
                    # If any of the times don't align within the parameter
                    if any( ( ( x < ( ts - within ) ) or ( x > ( ts + within ) ) )
                            for x in _xm_( curMatches, self.TIMESTAMP_PATH ) ):
                        continue
                    else:
                        nextMatches = curMatches + [ event ]
                        if 1 < len( remainingFeedStates ):
                            subMatches = findMatches( nextMatches, remainingFeedStates[ 1 : ] )
                            if 0 != len( subMatches ):
                                out.extend( subMatches )
                        else:
                            out.append( nextMatches )
            return out

        # Recursive linear search algorithm, yes not great, but expected number
        # of states in each feed is so small optimization shouldn't be required.
        out = findMatches( [], feedStates.values() )

        return out