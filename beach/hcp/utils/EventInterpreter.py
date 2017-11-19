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
import ipaddress
import traceback
import base64
import json
import uuid
_x_ = Actor.importLib( './hcp_helpers', '_x_' )
_xm_ = Actor.importLib( './hcp_helpers', '_xm_' )
exeFromPath = Actor.importLib( './hcp_helpers', 'exeFromPath' )
normalAtom = Actor.importLib( './hcp_helpers', 'normalAtom' )
ObjectTypes = Actor.importLib( './ObjectsDb', 'ObjectTypes' )

# The event tuples are: ( eventTypeDescription, funcForKey, funcForShortKey, funcForNarrative )

_eventTypes = {
    'notification.NEW_PROCESS' : ( 'new process starting',
                                   lambda x: _x_( x, '?/base.FILE_PATH' ),
                                   lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ),
                                   lambda x: 'The process %s with pid %s is starting.' % ( _x_( x, '?/base.FILE_PATH' ),
                                                                                           _x_( x, '?/base.PROCESS_ID' ) ),
                                   lambda x: ( exeFromPath( _x_( x, '?/base.FILE_PATH' ) ), ObjectTypes.PROCESS_NAME ) ),
    'notification.EXISTING_PROCESS' : ( 'pre-existing process',
                                   lambda x: _x_( x, '?/base.FILE_PATH' ),
                                   lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ),
                                   lambda x: 'The process %s with pid %s is already running.' % ( _x_( x, '?/base.FILE_PATH' ),
                                                                                                  _x_( x, '?/base.PROCESS_ID' ) ),
                                   lambda x: ( exeFromPath( _x_( x, '?/base.FILE_PATH' ) ), ObjectTypes.PROCESS_NAME ) ),
    'notification.TERMINATE_PROCESS' : ( 'a process is terminating',
                                         lambda x: _x_( x, '?/base.PROCESS_ID' ),
                                         lambda x: _x_( x, '?/base.PROCESS_ID' ),
                                         lambda x: 'The process with pid %s is terminating.' % ( _x_( x, '?/base.PROCESS_ID' ), ),
                                         lambda x: ( None, None ) ),
    'notification.CODE_IDENTITY' : ( 'new unique code executed',
                                     lambda x: _x_( x, '?/base.FILE_PATH' ),
                                     lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ),
                                     lambda x: 'The code on disk at %s was executed for the first time.' % ( _x_( x, '?/base.FILE_PATH' ), ),
                                     lambda x: ( _x_( x, '?/base.HASH' ), ObjectTypes.FILE_HASH ) ),
    'notification.DNS_REQUEST' : ( 'new domain name request',
                                   lambda x: _x_( x, '?/base.DOMAIN_NAME' ),
                                   lambda x: _x_( x, '?/base.DOMAIN_NAME' ),
                                   lambda x: 'A request for the domain name %s.' % ( _x_( x, '?/base.DOMAIN_NAME' ), ),
                                   lambda x: ( _x_( x, '?/base.DOMAIN_NAME' ), ObjectTypes.DOMAIN_NAME ) ),
    'notification.MODULE_LOAD' : ( 'a module is being loaded',
                                   lambda x: _x_( x, '?/base.FILE_PATH' ),
                                   lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ),
                                   lambda x: 'The code on disk at %s was loaded into %s.' % ( _x_( x, '?/base.FILE_PATH' ),
                                                                                              _x_( x, '?/base.PROCESS_ID' ) ),
                                   lambda x: ( exeFromPath( _x_( x, '?/base.FILE_PATH' ) ), ObjectTypes.MODULE_NAME ) ),
    'notification.FILE_CREATE' : ( 'a file is created',
                                   lambda x: _x_( x, '?/base.FILE_PATH' ),
                                   lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ),
                                   lambda x: 'The process %s created the file %s.' % ( _x_( x, '?/base.PROCESS_ID' ),
                                                                                       _x_( x, '?/base.FILE_PATH' ) ),
                                   lambda x: ( None, None ) ),
    'notification.FILE_DELETE' : ( 'a file is deleted',
                                   lambda x: _x_( x, '?/base.FILE_PATH' ),
                                   lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ),
                                   lambda x: 'The process %s deleted the file %s.' % ( _x_( x, '?/base.PROCESS_ID' ),
                                                                                       _x_( x, '?/base.FILE_PATH' ) ),
                                   lambda x: ( None, None ) ),
    'notification.FILE_MODIFIED' : ( 'a file is modified',
                                     lambda x: _x_( x, '?/base.FILE_PATH' ),
                                     lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ),
                                     lambda x: 'The process %s modified the file %s.' % ( _x_( x, '?/base.PROCESS_ID' ),
                                                                                          _x_( x, '?/base.FILE_PATH' ) ),
                                     lambda x: ( None, None ) ),
    'notification.FILE_READ' : ( 'a file is read',
                                 lambda x: _x_( x, '?/base.FILE_PATH' ),
                                 lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ),
                                 lambda x: 'The process %s read the file %s.' % ( _x_( x, '?/base.PROCESS_ID' ),
                                                                                  _x_( x, '?/base.FILE_PATH' ) ),
                                 lambda x: ( None, None ) ),
}

def _sanitizeJson( o, summarized = False ):
    if type( o ) is dict:
        for k, v in o.iteritems():
            o[ k ] = _sanitizeJson( v, summarized = summarized )
    elif type( o ) is list or type( o ) is tuple:
        o = [ _sanitizeJson( x, summarized = summarized ) for x in o ]
    elif type( o ) is uuid.UUID:
        o = str( o )
    else:
        try:
            if ( type(o) is str or type(o) is unicode ) and "\x00" in o: raise Exception()
            json.dumps( o )
        except:
            o = base64.b64encode( o )
        if summarized is not False and len( str( o ) ) > summarized:
            o = str( o[ : summarized ] ) + '...'
    return o

class EventInterpreter( object ):
    def __init__( self, event = None ):
        if event is not None:
            self.setEvent( event )

    def setEvent( self, event ):
        self.event = event
        self.eventType = event.keys()[ 0 ]

    def description( self ):
        return _eventTypes.get( self.eventType, ( None, None, None, None ) )[ 0 ]

    def name( self ):
        return self.eventType.split( '.' )[ -1 ]

    def key( self ):
        f = _eventTypes.get( self.eventType, ( None, None, None, None ) )[ 1 ]
        if f is not None:
            return f( self.event )
        else:
            return None

    def shortKey( self ):
        f = _eventTypes.get( self.eventType, ( None, None, None, None ) )[ 2 ]
        if f is not None:
            return f( self.event )
        else:
            return None

    def narrative( self ):
        f = _eventTypes.get( self.eventType, ( None, None, None, None ) )[ 3 ]
        if f is not None:
            return f( self.event )
        else:
            return None

    def object( self ):
        f = _eventTypes.get( self.eventType, ( None, None, None, None ) )[ 4 ]
        if f is not None:
            return f( self.event )
        else:
            return ( None, None )

    def getAtom( self ):
        return normalAtom( _x_( self.event, '?/hbs.THIS_ATOM' ) )

    def getParentAtom( self ):
        return normalAtom( _x_( self.event, '?/hbs.PARENT_ATOM' ) )

    def __str__( self ):
        return '%s( %s )' % ( self.name(), self.key() )

    def getTimestamp( self ):
        return _x_( self.event, '?/base.TIMESTAMP' )

class EventDSL( object ):
    __slots__ = [ 'data', 'mtd', 'dataType', '_isCaseSensitive', '_reFlags', '_ops' ]

    def __init__( self, event, mtd, isCaseSensitive = False ):
        self.data = event
        self.mtd = mtd
        try:
            self.dataType = event.keys()[ 0 ]
        except:
            self.dataType = None
        self._isCaseSensitive = isCaseSensitive
        self._reFlags = 0 if isCaseSensitive else re.IGNORECASE
        self._ops = { 'path' : lambda e, v: _x_( e, '?/base.FILE_PATH' ) == v,
                      'pathEndsWith' : lambda e, v: re.match( '.*%s$' % re.escape( v ), _x_( e, '?/base.FILE_PATH' ), self._reFlags ),
                      'pathStartsWith' : lambda e, v: re.match( '^%s.*' % re.escape( v ), _x_( e, '?/base.FILE_PATH' ), self._reFlags ),
                      'pathMatches' : lambda e, v: re.match( v, _x_( e, '?/base.FILE_PATH' ), self._reFlags ),
                      'commandLine' : lambda e, v: _x_( e, '?/base.COMMAND_LINE' ) == v,
                      'commandLineEndsWith' : lambda e, v: re.match( '.*%s$' % re.escape( v ), _x_( e, '?/base.COMMAND_LINE' ), self._reFlags ),
                      'commandLineStartsWith' : lambda e, v: re.match( '^%s.*' % re.escape( v ), _x_( e, '?/base.COMMAND_LINE' ), self._reFlags ),
                      'commandLineMatches' : lambda e, v: re.match( v, _x_( e, '?/base.COMMAND_LINE' ), self._reFlags ),
                      'user' : lambda e, v: _x_( e, '?/base.USER_NAME' ) == v,
                      'userEndsWith' : lambda e, v: re.match( '.*%s$' % re.escape( v ), _x_( e, '?/base.USER_NAME' ), self._reFlags ),
                      'userStartsWith' : lambda e, v: re.match( '^%s.*' % re.escape( v ), _x_( e, '?/base.USER_NAME' ), self._reFlags ),
                      'userMatches' : lambda e, v: re.match( v, _x_( e, '?/base.USER_NAME' ), self._reFlags ),
                      'domain' : lambda e, v: _x_( e, '?/base.DOMAIN_NAME' ) == v,
                      'domainEndsWith' : lambda e, v: re.match( '.*%s$' % re.escape( v ), _x_( e, '?/base.DOMAIN_NAME' ), self._reFlags ),
                      'domainStartsWith' : lambda e, v: re.match( '^%s.*' % re.escape( v ), _x_( e, '?/base.DOMAIN_NAME' ), self._reFlags ),
                      'domainMatches' : lambda e, v: re.match( v, _x_( e, '?/base.DOMAIN_NAME' ), re.IGNORECASE ),
                      'cname' : lambda e, v: _x_( e, '?/base.CNAME' ) == v,
                      'cnameEndsWith' : lambda e, v: re.match( '.*%s$' % re.escape( v ), _x_( e, '?/base.CNAME' ), self._reFlags ),
                      'cnameStartsWith' : lambda e, v: re.match( '^%s.*' % re.escape( v ), _x_( e, '?/base.CNAME' ), self._reFlags ),
                      'cnameMatches' : lambda e, v: re.match( v, _x_( e, '?/base.CNAME' ), re.IGNORECASE ),
                      'ip' : lambda e, v: _x_( e, '?/base.IP_ADDRESS' ) == v,
                      'ipEndsWith' : lambda e, v: re.match( '.*%s$' % re.escape( v ), _x_( e, '?/base.IP_ADDRESS' ), self._reFlags ),
                      'ipStartsWith' : lambda e, v: re.match( '^%s.*' % re.escape( v ), _x_( e, '?/base.IP_ADDRESS' ), self._reFlags ),
                      'ipIn' : lambda e, v: ipaddress.ip_address( unicode( _x_( e, '?/base.IP_ADDRESS' ) ) ) in ipaddress.ip_network( unicode( v ) ),
                      'hash' : lambda e, v: re.match( '^%s$' % re.escape( v ), _x_( e, '?/base.HASH' ).encode( 'hex' ), re.IGNORECASE ),
                      'userId' : lambda e, v: _x_( e, '?/base.USER_ID' ) == v,
                      'dstIpIn' : lambda e, v: ipaddress.ip_address( unicode( _x_( e, 'base.DESTINATION/base.IP_ADDRESS' ) ) ) in ipaddress.ip_network( unicode( v ) ),
                      'srcIpIn' : lambda e, v: ipaddress.ip_address( unicode( _x_( e, 'base.SOURCE/base.IP_ADDRESS' ) ) ) in ipaddress.ip_network( unicode( v ) ),
                      'dstPort' : lambda e, v: _x_( e, 'base.DESTINATION/base.PORT' ) == v,
                      'srcPort' : lambda e, v: _x_( e, 'base.SOURCE/base.PORT' ) == v,
                      'isOutgoing' : lambda e, v: ( 1 == _x_( e, 'base.IS_OUTGOING' ) ) is v }

    def asJSON( self ):
        return _sanitizeJson( self.data )

    def atom( self ):
        return normalAtom( _x_( self.data, '?/hbs.THIS_ATOM' ) )

    def parentAtom( self ):
        return normalAtom( _x_( self.data, '?/hbs.PARENT_ATOM' ) )

    def Event( self, **kwargs ):
        if isinstance( self.data, dict ):
            e = self.data
            for k, v in kwargs.iteritems():
                if k not in self._ops:
                    raise Exception( 'Detection Lambda operation "%s" invalid!' % k )
                try:
                    if not self._ops[ k ]( e, v ):
                        return False
                except:
                    print( traceback.format_exc() )
                    return False
            return True
        elif isinstance( self.data, list ):
            for e in self.data:
                isMatch = True
                for k, v in kwargs.iteritems():
                    if k not in self._ops:
                        raise Exception( 'Detection Lambda operation "%s" invalid!' % k )
                    try:
                        if not self._ops[ k ]( e, v ):
                            isMatch = False
                            break
                    except:
                        print( traceback.format_exc() )
                        isMatch = False
                        break
                if isMatch:
                    return True
            return False

    def Process( self, **kwargs ):
        if self.dataType in ( 'notification.EXISTING_PROCESS', 
                                'notification.NEW_PROCESS' ):
            return self.Event( **kwargs )
        elif self.dataType in ( 'notification.NETWORK_SUMMARY', ):
            subEvent = _x_( self.data, '?/base.PROCESS' )
            if subEvent is None:
                return False
            tmpEvent = EventDSL( { "_" : subEvent }, self.mtd )
            return tmpEvent.Event( **kwargs )
        return False

    def ParentProcess( self, **kwargs ):
        if self.dataType in ( 'notification.EXISTING_PROCESS', 
                                'notification.NEW_PROCESS' ):
            subEvent = self.data.get( 'base.PARENT', None )
            if subEvent is None:
                return False
            tmpEvent = EventDSL( { "_" : subEvent }, self.mtd )
            return tmpEvent.Event( **kwargs )
        elif self.dataType in ( 'notification.NETWORK_SUMMARY', ):
            subEvent = _x_( self.data, '?/base.PROCESS/base.PARENT' )
            if subEvent is None:
                return False
            tmpEvent = EventDSL( { "_" : subEvent }, self.mtd )
        return False

    def Dns( self, **kwargs ):
        if 'notification.DNS_REQUEST' == self.dataType:
            return self.Event( **kwargs )
        return False

    def Hash( self, **kwargs ):
        if self.dataType in ( 'notification.CODE_IDENTITY', 
                                'notification.ONGOING_IDENTITY' ):
            return self.Event( **kwargs )
        return False

    def NetworkSummary( self, **kwargs ):
        if 'notification.NETWORK_SUMMARY' == self.dataType:
            return self.Event( **kwargs )
        return False

    def Connections( self, **kwargs ):
        if self.dataType in ( 'notification.NETWORK_SUMMARY', ):
            subEvent = _xm_( self.data, '?/base.PROCESS/base.NETWORK_ACTIVITY' )
            if subEvent is None:
                return False
            tmpEvent = EventDSL( subEvent, self.mtd )
            return tmpEvent.Event( **kwargs )
        return False

    def UserObserved( self, **kwargs ):
        if 'notification.USER_OBSERVED' == self.dataType:
            return self.Event( **kwargs )
        return False

    def StartingUp( self, **kwargs ):
        if 'notification.STARTING_UP' == self.dataType:
            return self.Event( **kwargs )
        return False

    def Sync( self, **kwargs ):
        if 'notification.SYNC' == self.dataType:
            return self.Event( **kwargs )
        return False

    def Detection( self, name = None, **kwargs ):
        if self.dataType.startswith( 'detection_' ):
            if name is not None and self.dataType != ( 'detection_%s' % name ):
                return False
            return self.Event( **kwargs )
        return False