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

import sys
import os
import re
import datetime
from collections import OrderedDict
import collections
import functools
from functools import wraps
import inspect
from contextlib import contextmanager
import gevent.queue
import gevent.pool
import gevent

try:
    from beach.actor import Actor
    rSequence = Actor.importLib( './rpcm', 'rSequence' )
except:
    from rpcm import rSequence

try:
    import gevent.lock
    import gevent.event
except:
    print( "gevent not installed, some functionality won't work" )

import uuid

import hmac, base64, struct, hashlib, time, string, random

class Event ( object ):
    def __init__( self ):
        self._event = gevent.event.Event()

    def wait( self, timeout = None ):
        return self._event.wait( timeout )

    def set( self ):
        return self._event.set()

    def clear( self ):
        return self._event.clear()

def _xm_( o, path, isWildcardDepth = False ):
    def _isDynamicType( e ):
        eType = type( e )
        return issubclass( eType, dict ) or issubclass( eType, list ) or issubclass( eType, tuple )

    def _isListType( e ):
        eType = type( e )
        return issubclass( eType, list ) or issubclass( eType, tuple )

    def _isSeqType( e ):
        eType = type( e )
        return issubclass( eType, dict )

    result = []
    oType = type( o )

    if type( path ) is str or type( path ) is unicode:
        tokens = [ x for x in path.split( '/' ) if x != '' ]
    else:
        tokens = path

    if issubclass( oType, dict ):
        isEndPoint = False
        if 0 != len( tokens ):
            if 1 == len( tokens ):
                isEndPoint = True

            curToken = tokens[ 0 ]

            if '*' == curToken:
                if 1 < len( tokens ):
                    result = _xm_( o, tokens[ 1 : ], True )
            elif '?' == curToken:
                if 1 < len( tokens ):
                    result = []
                    for elem in o.itervalues():
                        if _isDynamicType( elem ):
                            result += _xm_( elem, tokens[ 1 : ], False )

            elif o.has_key( curToken ):
                if isEndPoint:
                    result = [ o[ curToken ] ] if not _isListType( o[ curToken ] ) else o[ curToken ]
                elif _isDynamicType( o[ curToken ] ):
                    result = _xm_( o[ curToken ], tokens[ 1 : ] )

            if isWildcardDepth:
                tmpTokens = tokens[ : ]
                for elem in o.itervalues():
                    if _isDynamicType( elem ):
                        result += _xm_( elem, tmpTokens, True )
    elif issubclass( oType, list ) or oType is tuple:
        result = []
        for elem in o:
            if _isDynamicType( elem ):
                result += _xm_( elem, tokens )

    return result

def _x_( o, path, isWildcardDepth = False ):
    r = _xm_( o, path, isWildcardDepth )
    if 0 != len( r ):
        r = r[ 0 ]
    else:
        r = None
    return r

def exeFromPath( path, agent = None ):
    if path is None:
        return None
    if agent is None or agent.isWindows():
        i = path.rfind( '\\' )
        j = path.rfind( '/' )
        i = max( i, j )
        if -1 != i:
            exeName = path[ i + 1 : ]
        else:
            exeName = path
    else:
        i = path.rfind( '/' )
        if -1 != i:
            exeName = path[ i + 1 : ]
        else:
            exeName = path
    return exeName

def hexDump( src, length = 8 ):
    result = []
    for i in xrange( 0, len( src ), length ):
       s = src[ i : i + length ]
       hexa = ' '.join( [ "%02X" % ord( x ) for x in s ] )
       printable = s.translate( ''.join( [ ( len( repr( chr( x ) ) ) == 3 ) and chr( x ) or '.' for x in range( 256 ) ] ) )
       result.append( "%04X   %-*s   %s\n" % ( i, length * 3, hexa, printable ) )
    return ''.join( result )

class HcpModuleId( object ):
    BOOTSTRAP = 0
    HCP = 1
    HBS = 2
    TEST = 3
    AAD = 4
    KERNEL_ACQ = 5
    BULK_COLLECTOR = 6

class HbsCollectorId ( object ):
    EXFIL = 0
    PROCESS_TRACKER = 1
    DNS_TRACKER = 2
    CODE_IDENT = 3
    NETWORK_TRACKER = 4
    HIDDEN_MODULE = 5
    MODULE_TRACKER = 6
    FILE_TRACKER = 7
    NETWORK_SUMMARY = 8
    FILE_FORENSIC = 9
    MEMORY_FORENSIC = 10
    OS_FORENSIC = 11
    _AVAILABLE = 12
    EXEC_OOB = 13
    DENY_TREE = 14
    PROCESS_HOLLOWING = 15
    YARA = 16
    OS_TRACKER = 17
    DOC_COLLECTOR = 18
    VOLUME_TRACKER = 19
    STATEFUL_TRACKING = 20
    USER_TRACKER = 21
    FILE_TYPE_TRACKER = 22

    lookup = {
        0 : 'EXFIL',
        1 : 'PROCESS_TRACKER',
        2 : 'DNS_TRACKER',
        3 : 'CODE_IDENT',
        4 : 'NETWORK_TRACKER',
        5 : 'HIDDEN_MODULE',
        6 : 'MODULE_TRACKER',
        7 : 'FILE_TRACKER',
        8 : 'NETWORK_SUMMARY',
        9 : 'FILE_FORENSIC',
        10 : 'MEMORY_FORENSIC',
        11 : 'OS_FORENSIC',
        12 : '_AVAILABLE',
        13 : 'EXEC_OOB',
        14 : 'DENY_TREE',
        15 : 'PROCESS_HOLLOWING',
        16 : 'YARA',
        17 : 'OS_TRACKER',
        18 : 'DOC_COLLECTOR',
        19 : 'VOLUME_TRACKER',
        20 : 'STATEFUL_TRACKING',
        21 : 'USER_TRACKER',
        22 : 'FILE_TYPE_TRACKER'
    }

class InvestigationNature:
    OPEN = 0
    FALSE_POSITIVE = 1
    UNWANTED_SOFTWARE = 2
    INSIDER_ACTIVITY = 3
    COMMON_MALWARE = 4
    ADVANCED_MALWARE = 5
    INTRUDER = 6
    DATA_LEAK = 7
    TEST = 8
    DUPLICATE = 9
    RANSOMWARE = 10

    lookup = {
        0 : 'OPEN',
        1 : 'FALSE_POSITIVE',
        2 : 'UNWANTED_SOFTWARE',
        3 : 'INSIDER_ACTIVITY',
        4 : 'COMMON_MALWARE',
        5 : 'ADVANCED_MALWARE',
        6 : 'INTRUDER',
        7 : 'DATA_LEAK',
        8 : 'TEST',
        9 : 'DUPLICATE',
        10 : 'RANSOMWARE'
    }

class InvestigationConclusion:
    RUNNING = 0
    REQUIRES_HUMAN = 1
    MITIGATED = 2
    CONTAINED = 3
    NO_ACTION_TAKEN = 4

    lookup = {
        0 : 'RUNNING',
        1 : 'REQUIRES_HUMAN',
        2 : 'MITIGATED',
        3 : 'CONTAINED',
        4 : 'NO_ACTION_TAKEN'
    }

class MemoryAccess:
    DENIED = 0x00
    EXECUTE = 0x01
    EXECUTE_READ = 0x02
    EXECUTE_READ_WRITE = 0x03
    EXECUTE_WRITE_COPY = 0x04
    NO_ACCESS = 0x05
    READ_ONLY = 0x06
    READ_WRITE = 0x07
    WRITE_COPY = 0x08
    WRITE_ONLY = 0x09
    EXECUTE_WRITE = 0x0A

    lookup = {
        0x00 : 'DENIED',
        0x01 : 'EXECUTE',
        0x02 : 'EXECUTE_READ',
        0x03 : 'EXECUTE_READ_WRITE',
        0x04 : 'EXECUTE_WRITE_COPY',
        0x05 : 'NO_ACCESS',
        0x06 : 'READ_ONLY',
        0x07 : 'READ_WRITE',
        0x08 : 'WRITE_COPY',
        0x09 : 'WRITE_ONLY',
        0x0A : 'EXECUTE_WRITE'
    }

class MemoryType:
    UNKNOWN = 0
    IMAGE = 1
    MAPPED = 2
    PRIVATE = 3
    EMPTY = 4
    SHARED = 5

    lookup = {
        0 : 'UNKNOWN',
        1 : 'IMAGE',
        2 : 'MAPPED',
        3 : 'PRIVATE',
        4 : 'EMPTY',
        5 : 'SHARED'
    }

def isModuleAvailable( module ):
    import imp
    try:
        imp.find_module( module )
        found = True
    except ImportError:
        found = False
    return found

re_ip_to_tuple = re.compile( '^(\d+)\.(\d+)\.(\d+)\.(\d+)$' )
def ip_to_tuple( ip ):
    global re_ip_to_tuple
    tup = None
    
    matches = re_ip_to_tuple.match( ip )
    if matches:
        matches = matches.groups( 0 )
        tup = [ matches[ 0 ], matches[ 1 ], matches[ 2 ], matches[ 3 ] ]
    
    return tup

def chunks( l, n ):
    """ Yield successive n-sized chunks from l.
    """
    tmp = None
    for i in l:
        if tmp is None:
            tmp = []
        tmp.append( i )
        if n == len( tmp ):
            yield tmp
            tmp = None
    if tmp is not None:
        yield tmp

def tsToTime( ts ):
    return datetime.datetime.fromtimestamp( int( ts ) ).strftime( '%Y-%m-%d %H:%M:%S' )

def timeToTs( timeStr ):
    return time.mktime( datetime.datetime.strptime( str( timeStr ).split( '.' )[ 0 ], '%Y-%m-%d %H:%M:%S' ).timetuple() )

def anyOf( coll, f = None ):
    ''' Like the builtin 'any' function but this will short-circuit eval.'''
    for i in coll:
        if ( f is None and i ) or ( f is not None and f( i ) ):
            return True
    return False

def allOf( coll, f ):
    ''' Like the builtin 'all' function but this will short-circuit eval.'''
    if 0 == len( coll ): return False
    for i in coll:
        if ( f is None and not i ) or ( f is not None and not f( i ) ):
            return False
    return True

def anyOfIn( c1, c2 ):
    return anyOf( c1, lambda x: x in c2 )

def traceThisLine( **kwargs ):
    ''' SImple debugging tool, will print to stderr the info on locations of caller of this function as well as any keyword arguments you passed to it.'''
    ( frame, filename, line_number, function_name, lines, index ) = inspect.getouterframes( inspect.currentframe() )[ 1 ]
    sys.stderr.write( "%s - %s::%s : %s =  %s\n" % ( time.time(), filename, function_name, line_number, str( kwargs ) ) )
    sys.stderr.flush()
    

@contextmanager
def file_lock( lock_file ):
    ''' Designed to be used with the "with" operator.
        with file_lock( "/tmp/myfile" ):
            print( "some stuff" )
    '''
    if os.path.exists(lock_file):
        print 'Only one script can run at once. '\
              'Script is locked with %s' % lock_file
        sys.exit(-1)
    else:
        open(lock_file, 'w').write("1")
        try:
            yield
        finally:
            os.remove(lock_file)

def timedFunction( f ):
    ''' Decorator to do basic timing over a function. '''
    @wraps( f )
    def wrapped( *args, **kwargs ):
        start = time.time()
        r = f( *args, **kwargs )
        print( "%s: %s" % ( f.__name__, time.time() - start ) )
        return r
    return wrapped

class Mutex( object ):
    def __init__( self ):
        self._sem = gevent.lock.BoundedSemaphore( value = 1 )

    def lock( self, timeout = None ):
        return self._sem.acquire( blocking = True, timeout = timeout )

    def unlock( self ):
        return self._sem.release()

    def __enter__( self ):
        self.lock()

    def __exit__( self, type, value, traceback ):
        self.unlock()

class _rwlock_w( object ):
    def __init__( self, l ):
        self.l = l
    def __enter__( self ):
        self.l.wLock()
        return self
    def __exit__( self, type, value, traceback ):
        self.l.wUnlock()

class _rwlock_r( object ):
    def __init__( self, l ):
        self.l = l
    def __enter__( self ):
        self.l.rLock()
        return self
    def __exit__( self, type, value, traceback ):
        self.l.rUnlock()

class RWLock( object ):
    def __init__( self, nReaders ):
        self._nReaders = nReaders
        self._sem = gevent.lock.BoundedSemaphore( value = nReaders )

    def rLock( self, timeout = None ):
        return self._sem.acquire( blocking = True, timeout = timeout )

    def rUnlock( self ):
        return self._sem.release()

    def wLock( self, timeout = None ):
        nLocked = 0
        for n in range( self._nReaders ):
            if self._sem.acquire( blocking = True, timeout = timeout ):
                nLocked += 1
        if nLocked != self._nReaders:
            for n in range( nLocked ):
                self._sem.release()
            return False
        else:
            return True

    def wUnlock( self ):
        for n in range( self._nReaders ):
            self._sem.release()

    def writer( self ):
        return _rwlock_w( self )

    def reader( self ):
        return _rwlock_r( self )


class AgentId( object ):
    
    empty_uuid = uuid.UUID( bytes = "\x00" * 16 )
    re_agent_id = re.compile( r'^((?:[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12})|(?:0))(?:\.((?:[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12})|(?:0))\.((?:[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12})|(?:0))\.([0-9a-fA-F]+)\.([0-9a-fA-F]+))?$' )

    PLATFORM_WINDOWS = 0x10000000
    PLATFORM_LINUX = 0x20000000
    PLATFORM_MACOS = 0x30000000
    PLATFORM_IOS = 0x40000000
    PLATFORM_ANDROID = 0x50000000

    ARCHITECTURE_X86 = 0x00000001
    ARCHITECTURE_X64 = 0x00000002

    def __init__( self, seq ):
        self.sensor_id = None
        self.org_id = None
        self.ins_id = None
        self.architecture = None
        self.platform = None

        if type( seq ) is rSequence or type( seq ) is dict:
            self.sensor_id = seq.get( 'base.HCP_SENSOR_ID', seq.get( 'sensor_id', None ) )
            self.org_id = seq.get( 'base.HCP_ORG_ID', seq.get( 'org_id', None ) )
            self.ins_id = seq.get( 'base.HCP_INSTALLER_ID', seq.get( 'ins_id', None ) )
            self.architecture = seq.get( 'base.HCP_ARCHITECTURE', seq.get( 'architecture', None ) )
            self.platform = seq.get( 'base.HCP_PLATFORM', seq.get( 'platform', None ) )

            if self.sensor_id is not None:
                self.sensor_id = uuid.UUID( bytes = self.sensor_id )
                if self.sensor_id == self.empty_uuid:
                    self.sensor_id = None

            if self.org_id is not None:
                self.org_id = uuid.UUID( bytes = self.org_id )
                if self.org_id == self.empty_uuid:
                    self.org_id = None

            if self.ins_id is not None:
                self.ins_id = uuid.UUID( bytes = self.ins_id )
                if self.ins_id == self.empty_uuid:
                    self.ins_id = None

            if self.architecture is not None:
                self.architecture = int( self.architecture )
            if self.platform is not None:
                self.platform = int( self.platform )
                
        elif type( seq ) is str or type( seq ) is unicode or type( seq ) is uuid.UUID:
            seq = str( seq )
            matches = self.re_agent_id.match( seq )
            if matches is not None:
                matches = matches.groups()
                if matches[ 1 ] is None:
                    self.sensor_id = uuid.UUID( matches[ 0 ] )
                else:
                    self.org_id = matches[ 0 ]
                    if self.org_id == '0' or self.org_id == self.empty_uuid:
                        self.org_id = None
                    else:
                        self.org_id = uuid.UUID( self.org_id )
                    self.ins_id = matches[ 1 ]
                    if self.ins_id == '0' or self.ins_id == self.empty_uuid:
                        self.ins_id = None
                    else:
                        self.ins_id = uuid.UUID( self.ins_id )
                    self.sensor_id = matches[ 2 ]
                    if self.sensor_id == '0' or self.sensor_id == self.empty_uuid:
                        self.sensor_id = None
                    else:
                        self.sensor_id = uuid.UUID( self.sensor_id )
                    self.platform = int( matches[ 3 ], 16 ) if int( matches[ 3 ], 16 ) != 0 else None
                    self.architecture = int( matches[ 4 ], 16 ) if int( matches[ 4 ], 16 ) != 0 else None
            else:
                raise Exception( 'invalid agentid: %s' % str( seq ) )
        elif type( seq ) is list or type( seq ) is tuple:
            if 1 == len( seq ):
                self.sensor_id = seq[ 0 ]
                if '0' == self.sensor_id or self.empty_uuid == self.sensor_id:
                    self.sensor_id = None
                elif self.sensor_id is not None:
                    self.sensor_id = uuid.UUID( self.sensor_id )
            else:
                self.org_id = str( seq[ 0 ] ) if seq[ 0 ] is not None else None
                self.ins_id = str( seq[ 1 ] ) if seq[ 1 ] is not None else None
                self.sensor_id = str( seq[ 2 ] ) if seq[ 2 ] is not None else None
                self.platform = seq[ 3 ]
                self.architecture = seq[ 4 ]

                if '0' == self.org_id or str( self.empty_uuid ) == self.org_id:
                    self.org_id = None
                elif self.org_id is not None:
                    self.org_id = uuid.UUID( self.org_id )

                if '0' == self.ins_id or str( self.empty_uuid ) == self.ins_id:
                    self.ins_id = None
                elif self.ins_id is not None:
                    self.ins_id = uuid.UUID( self.ins_id )

                if '0' == self.sensor_id or str( self.empty_uuid ) == self.sensor_id:
                    self.sensor_id = None
                elif self.sensor_id is not None:
                    self.sensor_id = uuid.UUID( self.sensor_id )

                if self.architecture is not None:
                    self.architecture = int( self.architecture )
                if self.platform is not None:
                    self.platform = int( self.platform )
        elif type( seq ) is AgentId:
            self.sensor_id = seq.sensor_id
            self.org_id = seq.org_id
            self.ins_id = seq.ins_id
            self.architecture = seq.architecture
            self.platform = seq.platform
        else:
            raise Exception( 'invalid agentid: %s' % str( seq ) )

    def asWhere( self ):
        filt = []
        filtValues = []

        if self.sensor_id is not None:
            filt.append( 'sid = %s' )
            filtValues.append( self.sensor_id )
        if self.org_id is not None:
            filt.append( 'oid = %s' )
            filtValues.append( self.org_id )

        return ( ' AND '.join( filt ), filtValues )

    def asString( self ) :
        s = '%s.%s.%s.%s.%s' % ( self.org_id if self.org_id is not None else '0',
                                 self.ins_id if self.ins_id is not None else '0',
                                 self.sensor_id if self.sensor_id is not None else '0',
                                 hex( self.platform )[ 2 : ] if self.platform is not None else '0',
                                 hex( self.architecture )[ 2 : ] if self.architecture is not None else '0' )

        return s

    def __str__( self ):
        return self.asString()

    def __repr__( self ):
        return 'AgentId( %s )' % self.asString()
        
    def __eq__( self, a ):
        return self.sensor_id == a.sensor_id
    
    def __ne__( self, a ):
        return not self.__eq__( a )
    
    def inSubnet( self, subnet ):    
        return ( ( self.org_id == subnet.org_id or subnet.org_id is None ) and
                 ( self.ins_id == subnet.ins_id or subnet.ins_id is None ) and
                 ( self.sensor_id == subnet.sensor_id or subnet.sensor_id is None ) and
                 ( self.architecture == subnet.architecture or subnet.architecture is None ) and
                 ( self.platform == subnet.platform or subnet.platform is None ) )
    
    def toJson( self ):
        return {
                'base.HCP_SENSOR_ID' : { 'tag' : 'base.HCP_SENSOR_ID', 
                                         'type' : 'buffer', 
                                         'value' : ( self.sensor_id if self.sensor_id is not None else self.empty_uuid ).bytes },
                'base.HCP_ORG_ID' : { 'tag' : 'base.HCP_ORG_ID', 
                                      'type' : 'buffer', 
                                      'value' : ( self.org_id if self.org_id is not None else self.empty_uuid ).bytes },
                'base.HCP_INSTALLER_ID' : { 'tag' : 'base.HCP_INSTALLER_ID', 
                                      'type' : 'buffer', 
                                      'value' : ( self.ins_id if self.ins_id is not None else self.empty_uuid ).bytes },
                'base.HCP_ARCHITECTURE' : { 'tag' : 'base.HCP_ARCHITECTURE', 
                                            'type' : 'int_32', 
                                            'value' : self.architecture },
                'base.HCP_PLATFORM' : { 'tag' : 'base.HCP_PLATFORM', 
                                        'type' : 'int_32', 
                                        'value' : self.platform }
            }
    
    def isWindows( self ):
        return self.platform == 0x10000000
    
    def isLinux( self ):
        return self.platform == 0x20000000
    
    def isMacOSX( self ):
        return self.platform == 0x30000000
    
    def isIos( self ):
        return self.platform == 0x40000000
    
    def isAndroid( self ):
        return self.platform == 0x50000000
    
    def isX86( self ):
        return self.architecture == 0x00000001

    def isX64( self ):
        return self.architecture == 0x00000002

    def isWildcarded( self ):
        return ( self.sensor_id is None and
                 ( self.org_id is None or
                   self.ins_id is None or
                   self.architecture is None or
                   self.platform is None ) )

    def architectureString( self ):
        if self.isX86():
            return 'x86'
        elif self.isX64():
            return 'x64'
        else:
            return '-'

    def platformString( self ):
        if self.isWindows():
            return 'Windows'
        elif self.isLinux():
            return 'Linux'
        elif self.isMacOSX():
            return 'macOS'
        elif self.isIos():
            return 'iOS'
        elif self.isAndroid():
            return 'Android'
        else:
            return '-'


class RingCache( object ):
    
    def __init__( self, maxEntries = 100, isAutoAdd = False ):
        self.max = maxEntries
        self.d = OrderedDict()
        self.isAutoAdd = isAutoAdd
    
    def add( self, k, v = None ):
        if self.max <= len( self.d ):
            self.d.popitem( last = False )
        if k in self.d:
            del( self.d[ k ] )
        self.d[ k ] = v
    
    def get( self, k ):
        return self.d[ k ]
    
    def remove( self, k ):
        del( self.d[ k ] )
    
    def __contains__( self, k ):
        if k in self.d:
            v = self.d[ k ]
            del( self.d[ k ] )
            self.d[ k ] = v
            return True
        else:
            if self.isAutoAdd:
                self.add( k )
            return False
    
    def __len__( self ):
        return len( self.d )
    
    def __repr__( self ):
        return self.d.__repr__()

class ringcached( object ):
    '''
    Ring Caching Decorator
    '''
    def __init__( self, func, maxEntries = 100 ):
        self.func = func
        self.maxEntries = maxEntries
        self.cache = RingCache( maxEntries )
        
    def __call__( self, *args ):
        if not isinstance( args, collections.Hashable ):
            # uncacheable. a list, for instance.
            # better to not cache than blow up.
            return self.func( *args )
        
        if args in self.cache:
            return self.cache.get( args )
        
        else:
            value = self.func( *args )
            self.cache.add( args, value )
            return value
        
    def __repr__( self ):
        return self.func.__doc__
    def __get__( self, obj, objtype ):
        return functools.partial( self.__call__, obj )

def synchronized( f ):
    '''Synchronization decorator.'''
    
    lock = Mutex()

    def new_function( *args, **kw ):
        lock.lock()
        try:
            return f( *args, **kw )
        finally:
            lock.unlock()

    return new_function


class HcpOperations:
    LOAD_MODULE = 1
    UNLOAD_MODULE = 2
    SET_HCP_ID = 3
    SET_GLOBAL_TIME = 4
    QUIT = 5

class PooledResource( object ):
    def __init__( self, resourceFactoryFunc, maxResources = None ):
        self._factory = resourceFactoryFunc
        self._resources = []
        self._maxResources = maxResources
        self._curResources = 0

    def acquire( self ):
        res = None
        if 0 != len( self._resources ):
            res = self._resources.pop()
        elif self._maxResources is None or self._maxResources > self._curResources:
            res = self._factory()
        return res

    def release( self, resource ):
        self._resources.append( resource )

    @contextmanager
    def anInstance( self, releaseOnException = False ):
        try:
            db = self.acquire()
            yield db
        except:
            if releaseOnException:
                self.release( db )
        else:
            self.release( db )

class CreateOnAccess( object ):
    def __init__( self, toCall, *args, **kwargs ):
        self._toCall = toCall
        self._args = args
        self._kwargs = kwargs
        self._instance = None
    def __getattr__(self, item):
        if self._instance is None:
            self._instance = self._toCall( *self._args, **self._kwargs )
        return getattr( self._instance, item )

def normalAtom( atom ):
    if atom is None: return None
    try:
        if type( atom ) is uuid.UUID:
            atom = str( atom )
        else:
            atom = str( uuid.UUID( atom ) )
    except:
        try:
            atom = str( uuid.UUID( bytes = atom ) )
        except:
            atom = str( uuid.UUID( bytes = base64.b64decode( atom.replace( ' ', '+' ) ) ) )
    return atom

class LimitedQPSBuffer( object ):
    def __init__( self, maxQps, cbLog = None ):
        self._maxQps = maxQps
        self._q = gevent.queue.Queue()
        self._log = cbLog
        self._transmitted = 0
        self._lastWait = time.time()
        self._isRunning = True
        self._threads = gevent.pool.Group()
        self._threads.add( gevent.spawn_later( 0, self._sendLoop ) )
        self._threads.add( gevent.spawn_later( 1, self._resetStats ) )

    def _resetStats( self ):
        if self._isRunning:
            self._transmitted = 0
            self._threads.add( gevent.spawn_later( 1, self._resetStats ) )

    def _sendLoop( self ):
        while self._isRunning:
            if self._transmitted >= self._maxQps:
                self._log( "slowing down (%s in queue)" % ( self._q.qsize(), ) )
                gevent.sleep( 1 )
            try:
                cb, items = self._q.get_nowait()
            except:
                gevent.sleep( 1 )
            else:
                self._transmitted += 1
                cb( *items )

    def add( self, cb, *items ):
        self._q.put_nowait( ( cb, items ) )

    def size( self ):
        return self._q.qsize()

    def close( self ):
        self._isRunning = False
        self._threads.join()