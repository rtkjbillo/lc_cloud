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

_x_ = Actor.importLib( './hcp_helpers', '_x_' )
_xm_ = Actor.importLib( './hcp_helpers', '_xm_' )
exeFromPath = Actor.importLib( './hcp_helpers', 'exeFromPath' )
ObjectTypes = Actor.importLib( './ObjectsDb', 'ObjectTypes' )
AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )
ObjectNormalForm = Actor.importLib( '../utils/ObjectsDb', 'ObjectNormalForm' )

class InvalidObjectException ( Exception ):
    pass

class EventObjectExtractor:
    _extractors = None

    @classmethod
    def extractFromEvent( cls, event, fromAgent ):
        if cls._extractors is None:
            cls._extractors = {
                'notification.NEW_PROCESS' : EventObjectExtractor._extractProcess,
                'notification.TERMINATE_PROCESS' : EventObjectExtractor._extractProcess,
                'notification.EXISTING_PROCESS' : EventObjectExtractor._extractProcess,
                'notification.DNS_REQUEST' : EventObjectExtractor._extractDns,
                'notification.OS_PROCESSES_REP' : EventObjectExtractor._extractProcessList,
                'notification.NETWORK_SUMMARY' : EventObjectExtractor._extractNetworkSummary,
                'notification.OS_SERVICES_REP' : EventObjectExtractor._extractServices,
                'notification.OS_DRIVERS_REP' : EventObjectExtractor._extractServices,
                'notification.OS_AUTORUNS_REP' : EventObjectExtractor._extractAutoruns,
                'notification.CODE_IDENTITY' : EventObjectExtractor._extractCodeIdent,
                'notification.USER_OBSERVED' : EventObjectExtractor._extractUserObserved,
            }

        objects = { 'obj' : {}, 'rel' : {} }

        eventType = event.keys()[ 0 ]
        eventRoot = event.values()[ 0 ]

        if eventType not in cls._extractors: return objects

        if type( fromAgent ) is not AgentId:
            fromAgent = AgentId( fromAgent )

        try:
            cls._extractors[ eventType ]( eventType, eventRoot, fromAgent, objects )
        except:
            raise InvalidObjectException( 'event contained invalid objects: %s' % str( event ) )

        cls._convertToNormalForm( objects, not fromAgent.isWindows() )

        return objects

    @classmethod
    def _extractProcess( cls, eventType, eventRoot, fromAgent, objects ):
        curExe = cls._extractProcessInfo( fromAgent, objects, eventRoot )
        parent = eventRoot.get( 'base.PARENT', None )
        user = eventRoot.get( 'base.USER_NAME', None )
        if user is not None:
            cls._addObj( eventRoot, objects, user, ObjectTypes.USER_NAME )
            if curExe is not None:
                cls._addRel( eventRoot, objects, user, ObjectTypes.USER_NAME, curExe, ObjectTypes.PROCESS_NAME )
        if parent is not None and curExe is not None:
            parentExe = cls._extractProcessInfo( fromAgent, objects, parent )
            if parentExe is not None:
                cls._addRel( eventRoot, objects, parentExe, ObjectTypes.PROCESS_NAME, curExe, ObjectTypes.PROCESS_NAME )

    @classmethod
    def _extractDns( cls, eventType, eventRoot, fromAgent, objects ):
        cls._addObj( eventRoot, objects, eventRoot[ 'base.DOMAIN_NAME' ], ObjectTypes.DOMAIN_NAME )


    @classmethod
    def _extractProcessList( cls, eventType, eventRoot, fromAgent, objects ):
        for p in eventRoot[ 'base.PROCESSES' ]:
            exe = cls._extractProcessInfo( fromAgent, objects, p )
            for m in p.get( 'base.MODULES', [] ):
                mod = cls._extractModuleInfo( fromAgent, objects, m )
                cls._addRel( eventRoot, 
                             objects, exe, ObjectTypes.PROCESS_NAME,
                             mod, ObjectTypes.MODULE_NAME )

    @classmethod
    def _extractNetworkSummary( cls, eventType, eventRoot, fromAgent, objects ):
        exe = cls._extractProcessInfo( fromAgent, objects, eventRoot )
        for c in eventRoot.get( 'base.NETWORK_ACTIVITY', [] ):
            port = c.get( 'base.DESTINATION', {} ).get( 'base.PORT', None )
            if port is not None:
                cls._addObj( eventRoot, objects, port, ObjectTypes.PORT )
                if exe is not None:
                    cls._addRel( eventRoot, objects, exe, ObjectTypes.PROCESS_NAME, port, ObjectTypes.PORT )

    @classmethod
    def _extractServices( cls, eventType, eventRoot, fromAgent, objects ):
        for s in eventRoot[ 'base.SVCS' ]:
            cls._extractServiceInfo( fromAgent, objects, s )

    @classmethod
    def _extractAutoruns( cls, eventType, eventRoot, fromAgent, objects ):
        for a in eventRoot[ 'base.AUTORUNS' ]:
            cls._extractAutorunsInfo( fromAgent, objects, a )

    @classmethod
    def _extractCodeIdent( cls, eventType, eventRoot, fromAgent, objects ):
        cls._extractCodeIdentityInfo( fromAgent, objects, eventRoot )

    @classmethod
    def _extractUserObserved( cls, eventType, eventRoot, fromAgent, objects ):
        user = eventRoot.get( 'base.USER_NAME', None )
        if user is not None:
            cls._addObj( eventRoot, objects, user, ObjectTypes.USER_NAME )




    @classmethod
    def _convertToNormalForm( cls, objects, isCaseSensitive ):
        k = []
        for oType in objects[ 'obj' ].keys():
            objects[ 'obj' ][ oType ] = [ ObjectNormalForm( x, oType, isCaseSensitive = isCaseSensitive ) for x in objects[ 'obj' ][ oType ] ]
        for ( parentType, childType ) in objects[ 'rel' ].keys():
            objects[ 'rel' ][ ( parentType, childType ) ] = [ ( ObjectNormalForm( x[ 0 ], 
                                                                                  parentType, 
                                                                                  isCaseSensitive = isCaseSensitive ), 
                                                                ObjectNormalForm( x[ 1 ], 
                                                                                  childType, 
                                                                                  isCaseSensitive = isCaseSensitive ) ) for x in objects[ 'rel' ][ ( parentType, childType ) ] ]

    @classmethod
    def _addObj( cls, root, objects, o, oType ):
        if type( o ) is not int:
            if o is None or 0 == len( o ) or 102400 < len( o ):
                raise InvalidObjectException()
        objects[ 'obj' ].setdefault( oType, Set() ).add( o )

    @classmethod
    def _addRel( cls, root, objects, parent, parentType, child, childType ):
        if type( parent ) is not int:
            if parent is None or 102400 < len( parent ):
                raise InvalidObjectException()
            elif 0 == len( parent ):
                return
        if type( child ) is not int:
            if child is None or 102400 < len( parent ):
                raise InvalidObjectException()
            elif 0 == len( child ):
                return
        objects[ 'rel' ].setdefault( ( parentType, childType ), Set() ).add( ( parent, child ) )

    @classmethod
    def _extractProcessInfo( cls, fromAgent, objects, procRoot ):
        exePath = procRoot.get( 'base.FILE_PATH', None )
        if exePath is not None and '' != exePath:
            cls._addObj( procRoot, objects, exePath, ObjectTypes.PROCESS_NAME )
            cmdLine = procRoot.get( 'base.COMMAND_LINE', None )
            if cmdLine is not None:
                cls._addObj( procRoot, objects, cmdLine, ObjectTypes.CMD_LINE )
                cls._addRel( procRoot, objects, exePath, ObjectTypes.PROCESS_NAME, cmdLine, ObjectTypes.CMD_LINE )
        return exePath

    @classmethod
    def _extractModuleInfo( cls, fromAgent, objects, modRoot ):
        modPath = modRoot.get( 'base.FILE_PATH', None )

        if modPath is not None:
            cls._addObj( modRoot, objects, modPath, ObjectTypes.MODULE_NAME )

        return mod

    @classmethod
    def _extractServiceInfo( cls, fromAgent, objects, svcRoot ):
        svcname = svcRoot.get( 'base.SVC_NAME', None )
        displayname = svcRoot.get( 'base.SVC_DISPLAY_NAME', None )
        exe = svcRoot.get( 'base.EXECUTABLE', None )
        dll = svcRoot.get( 'base.DLL', None )
        h = svcRoot.get( 'base.HASH', None )
        filePath = svcRoot.get( 'base.FILE_PATH', None )

        mainMod = exe
        if dll is not None:
            mainMod = dll

        if svcname is not None:
            cls._addObj( svcRoot, objects, svcname, ObjectTypes.SERVICE_NAME )
        if displayname is not None:
            cls._addObj( svcRoot, objects, displayname, ObjectTypes.SERVICE_NAME )

        if svcname is not None and displayname is not None:
            cls._addRel( svcRoot, objects, svcname, ObjectTypes.SERVICE_NAME, displayname, ObjectTypes.SERVICE_NAME )

        if mainMod is not None:
            cls._addObj( svcRoot, objects, mainMod, ObjectTypes.FILE_PATH )
            cls._addRel( svcRoot, objects, svcname, ObjectTypes.SERVICE_NAME, mainMod, ObjectTypes.FILE_PATH )

        if filePath is not None and '' != filePath:
            cls._addObj( svcRoot, objects, filePath, ObjectTypes.FILE_PATH )
            cls._addRel( svcRoot, objects, svcname, ObjectTypes.SERVICE_NAME, filePath, ObjectTypes.FILE_PATH )
        if h is not None:
            cls._addObj( svcRoot, objects, h, ObjectTypes.FILE_HASH )
            cls._addRel( svcRoot, objects, svcname, ObjectTypes.SERVICE_NAME, h, ObjectTypes.FILE_HASH )

    @classmethod
    def _extractAutorunsInfo( cls, fromAgent, objects, aRoot ):
        reg = aRoot.get( 'base.REGISTRY_KEY', None )
        path = aRoot.get( 'base.FILE_PATH', None )
        h = aRoot.get( 'base.HASH', None )
        autorun = None
        if path is not None and '' != path:
            autorun = path
        elif reg is not None:
            autorun = reg

        if autorun is not None:
            cls._addObj( aRoot, objects, autorun, ObjectTypes.AUTORUNS )
            if h is not None:
                cls._addObj( aRoot, objects, h, ObjectTypes.FILE_HASH )
                cls._addRel( aRoot, objects, autorun, ObjectTypes.AUTORUNS, h, ObjectTypes.FILE_HASH )

    @classmethod
    def _extractCodeIdentityInfo( cls, fromAgent, objects, cRoot ):
        filePath = cRoot.get( 'base.FILE_PATH', None )
        if filePath is None and '' != filePath:
            filePath = cRoot.get( 'base.DLL', None )
            if filePath is None:
                filePath = cRoot.get( 'base.EXECUTABLE', None )
        h = cRoot.get( 'base.HASH', None )

        if '' == filePath:
            filePath = None

        if filePath is not None:
            cls._addObj( cRoot, objects, filePath, ObjectTypes.MODULE_NAME )

        if h is not None:
            cls._addObj( cRoot, objects, h, ObjectTypes.FILE_HASH )
            if filePath is not None:
                cls._addRel( cRoot, objects, filePath, ObjectTypes.MODULE_NAME, h, ObjectTypes.FILE_HASH )

        #sig = cRoot.get( 'base.SIGNATURE', None )
        #if sig is not None:
        #    issuer = sig.get( 'base.CERT_ISSUER', None )
        #    if issuer is not None and filePath is not None:
        #        cls._addObj( cRoot, objects, issuer, ObjectTypes.CERT_ISSUER )
        #        cls._addRel( cRoot, objects, filePath, ObjectTypes.MODULE_NAME, issuer, ObjectTypes.CERT_ISSUER )