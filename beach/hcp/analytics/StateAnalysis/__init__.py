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
from sets import Set

_x_ = Actor.importLib( '../../hcp_helpers', '_x_' )
_xm_ = Actor.importLib( '../../hcp_helpers', '_xm_' )


_widgets = {}
def SAMLoadWidgets():
    global _widgets
    if 0 == len( _widgets ):
        _widgets.update( Actor.importLib( 'GenericWidgets', '*' ) )
        _widgets.update( Actor.importLib( 'ProcessWidgets', '*' ) )
        _widgets.update( Actor.importLib( 'TimeWidgets', '*' ) )
    return _widgets

class SAMInvalidStructureException( Exception ):
    pass

class SAMGcStrategy( object ):
    def __init__( self, widget ):
        self.widget = widget

    def collect_pre_all( self, feed, states, newEvent ):
        raise SAMInvalidStructureException( 'needs implementation' )

    def collect_pre( self, feed, feedState ):
        raise SAMInvalidStructureException( 'needs implementation' )

    def collect_post( self, feed, states ):
        raise SAMInvalidStructureException( 'needs implementation' )

    def collect_post_all( self, feed, states, newEvent ):
        raise SAMInvalidStructureException( 'needs implementation' )

class SAMWidget( object ):
    def __init__( self, parameters = {} ):
        self.parameters = parameters
        self.printDebug = parameters.get( 'debug', None )

    def log( self, msg ):
        if self.printDebug is not None:
            msg = '%s: %s' % ( self.__class__.__name__, msg )
            self.printDebug( msg )

    def _execute( self, newEvent ):
        raise SAMInvalidStructureException( 'needs implementation' )

class SAMFilter( SAMWidget ):
    def __init__( self, *a, **k ):
        SAMWidget.__init__( self, *a, **k )
        self._feeds = []

    def feedsFrom( self, widget ):
        self._feeds.append( widget )
        return self

    def feedsFromStream( self ):
        if 0 != len( self._feeds ):
            raise SAMInvalidStructureException( 'cannot feed from stream and from widgets simultaneously' )
        self._feeds = []
        return self

    def _execute( self, newEvent ):
        out = []

        if 0 == len( self._feeds ):
            # A filter's user functionality takes a single event and returns (or not)
            # a single event.
            eventProduced = self.execute( newEvent )
            if eventProduced is not None:
                # What a Widget returns is always a collection of states where a state
                # is itself a collection of events.
                out.append( [ eventProduced, ] )
        else:
            for feed in self._feeds:
                # Each feed produces an output as a Widget, so a collection of states
                # where each state is itslef a collection of events.
                out.extend( feed._execute( newEvent ) )

        return out

    def execute( self, newEvent ):
        raise SAMInvalidStructureException( 'needs implementation' )


class SAMState( SAMWidget ):
    def __init__( self, *a, **k ):
        SAMWidget.__init__( self, *a, **k )
        self._feeds = {}
        self._feedStates = {}
        self._feedGc = {}

    def feedsFrom( self, feedName, widget, gc ):
        self._feeds[ feedName ] = widget
        self._feedStates[ feedName ] = []
        self._feedGc[ feedName ] = gc( self )
        self._last_out = Set()
        return self

    def _execute( self, newEvent ):
        out = []
        forOut = []
        isNewInput = False

        if 0 == len( self._feeds ):
            raise SAMInvalidStructureException( 'state widgets require feeds' )

        for feedName in self._feeds.keys():
            self._feedGc[ feedName ].collect_pre_all( self._feeds[ feedName ],
                                                      self._feedStates[ feedName ],
                                                      newEvent )

        for feedName, feed in self._feeds.items():
            newStates = feed._execute( newEvent )
            if 0 != len( newStates ):
                isNewInput = True
                self._feedStates[ feedName ].extend( newStates )

        if isNewInput:
            for feedName in self._feeds.keys():
                self._feedGc[ feedName ].collect_pre( self._feeds[ feedName ],
                                                      self._feedStates[ feedName ] )

            forOut = self.execute( self._feedStates )

            for feedName in self._feeds.keys():
                self._feedGc[ feedName ].collect_post( self._feeds[ feedName ],
                                                       self._feedStates[ feedName ] )

        for feedName in self._feeds.keys():
            self._feedGc[ feedName ].collect_post_all( self._feeds[ feedName ],
                                                       self._feedStates[ feedName ],
                                                       newEvent )

        # Check to see if we have any change in output, if not we will not report it
        newOutState = Set( [ Set( [ e[ 'routing' ][ 'event_id' ] for e in s ] ) for s in forOut ] )
        for nSet in newOutState:
            if nSet not in self._last_out:
                self._last_out = newOutState
                out = forOut
                break

        return out

    def execute( self, *args, **kwargs ):
        raise SAMInvalidStructureException( 'needs implementation' )