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
import hashlib
import base64
import uuid
import msgpack
import sys
import time
import re
import time_uuid
AgentId = Actor.importLib( './hcp_helpers', 'AgentId' )
_ = Actor.importLib( 'Symbols', 'Symbols' )()
HbsCollectorId = Actor.importLib( './hcp_helpers', 'HbsCollectorId' )
rSequence = Actor.importLib( './rpcm', 'rSequence' )
rList = Actor.importLib( './rpcm', 'rList' )
rpcm = Actor.importLib( './rpcm', 'rpcm' )

class _collector( object ):
    def __init__( self ):
        self._isEnabled = True
        if hasattr( self, 'init' ):
            self.init()

    def enable( self ):
        self._isEnabled = True

    def disable( self ):
        self._isEnabled = False

    def isEnabled( self ):
        return self._isEnabled

    def toProfile( self ):
        profile = rSequence().addInt32( _.hbs.CONFIGURATION_ID, self.colId )
        if not self._isEnabled:
            profile.addInt8( _.base.IS_DISABLED, 1 )

        if hasattr( self, 'getProfile' ):
            return self.getProfile( profile )
        else:
            return profile

    def fromProfile( self, profile ):
        if hasattr( self, 'init' ):
            self.init()
        if hasattr( self, 'putProfile' ):
            self.putProfile( profile )

class _collector_0( _collector ):
    colId = HbsCollectorId.EXFIL
    
    def init( self ):
        self.exfil = Set()

    def addExfil( self, eventId ):
        self.exfil.add( int( eventId ) )

    def removeExfil( self, eventId ):
        self.exfil.remove( int( eventId ) )

    def getProfile( self, root ):
        exfilList = rList()

        for eId in self.exfil:
            exfilList.addInt32( _.hbs.NOTIFICATION_ID, eId )

        root.addList( _.hbs.LIST_NOTIFICATIONS, exfilList )

        return root

    def putProfile( self, root ):
        for event in root.get( _.hbs.LIST_NOTIFICATIONS, [] ):
            self.addExfil( event )

class _collector_1( _collector ):
    colId = HbsCollectorId.PROCESS_TRACKER

class _collector_2( _collector ):
    colId = HbsCollectorId.DNS_TRACKER

class _collector_3( _collector ):
    colId = HbsCollectorId.CODE_IDENT

class _collector_4( _collector ):
    colId = HbsCollectorId.NETWORK_TRACKER

class _collector_5( _collector ):
    colId = HbsCollectorId.HIDDEN_MODULE

class _collector_6( _collector ):
    colId = HbsCollectorId.MODULE_TRACKER

class _collector_7( _collector ):
    colId = HbsCollectorId.FILE_TRACKER

    def init( self ):
        self.enabledCreate = True
        self.enabledDelete = True
        self.enabledModified = True
        self.enabledRead = True

    def enableCreate( self ):
        self.enabledCreate = True

    def enableDelete( self ):
        self.enabledDelete = True

    def enableModified( self ):
        self.enabledModified = True

    def enableRead( self ):
        self.enabledRead = True

    def disableCreate( self ):
        self.enabledCreate = False

    def disableDelete( self ):
        self.enabledDelete = False

    def disableModified( self ):
        self.enabledModified = False

    def disableRead( self ):
        self.enabledRead = False

    def getProfile( self, root ):
        if not self.isEnabled(): return root
        
        disableList = rList()

        if not self.enabledCreate:
            disableList.addInt32( _.base.IS_DISABLED, _.notification.FILE_CREATE )

        if not self.enabledDelete:
            disableList.addInt32( _.base.IS_DISABLED, _.notification.FILE_DELETE )

        if not self.enabledModified:
            disableList.addInt32( _.base.IS_DISABLED, _.notification.FILE_MODIFIED )

        if not self.enabledRead:
            disableList.addInt32( _.base.IS_DISABLED, _.notification.FILE_READ )

        root.addList( _.base.IS_DISABLED, disableList )

        return root

    def putProfile( self, root ):
        for event in root.get( _.base.IS_DISABLED, [] ):
            if _.notification.FILE_CREATE == event:
                self.enabledCreate = False
            elif _.notification.FILE_DELETE == event:
                self.enabledDelete = False
            elif _.notification.FILE_MODIFIED == event:
                self.enabledModified = False
            elif _.notification.FILE_MODIFIED == event:
                self.enabledModified = False

class _collector_8( _collector ):
    colId = HbsCollectorId.NETWORK_SUMMARY

class _collector_9( _collector ):
    colId = HbsCollectorId.FILE_FORENSIC

class _collector_10( _collector ):
    colId = HbsCollectorId.MEMORY_FORENSIC

class _collector_11( _collector ):
    colId = HbsCollectorId.OS_FORENSIC

    def init( self ):
        self.freq = 0

    def setFrequency( self, freq ):
        self.freq = int( freq )

    def getProfile( self, root ):
        if 0 != self.freq:
            root.addTimedelta( _.base.TIMEDELTA, self.freq )

        return root

    def putProfile( self, root ):
        self.freq = root.get( _.base.TIMEDELTA, 0 )

class _collector_12( _collector ):
    colId = HbsCollectorId._AVAILABLE

class _collector_13( _collector ):
    colId = HbsCollectorId.EXEC_OOB

class _collector_14( _collector ):
    colId = HbsCollectorId._AVAILABLE2

class _collector_15( _collector ):
    colId = HbsCollectorId.PROCESS_HOLLOWING

class _collector_16( _collector ):
    colId = HbsCollectorId.YARA

class _collector_17( _collector ):
    colId = HbsCollectorId.OS_TRACKER

class _collector_18( _collector ):
    colId = HbsCollectorId.DOC_COLLECTOR

    def init( self ):
        self.extensions = Set()
        self.patterns = Set()

    def addExtension( self, extension ):
        self.extensions.add( extension )

    def removeExtension( self, ruleId, extension ):
        self.extensions.remove( extension )

    def addPattern( self, pattern ):
        self.patterns.add( pattern )

    def removePattern( self, pattern ):
        self.patterns.remove( pattern )

    def getProfile( self, root ):
        extList = rList()

        for extension in self.extensions:
            extList.addStringA( _.base.EXTENSION, extension )

        root.addList( _.base.EXTENSIONS, extList )

        patList = rList()
        for pattern in self.patterns:
            patList.addStringA( _.base.STRING_PATTERN, pattern )

        root.addList( _.base.PATTERNS, patList )

        return root

    def putProfile( self, root ):
        for extension in root.get( _.base.EXTENSIONS, [] ):
            self.addExtension( extension )

        for pattern in root.get( _.base.STRING_PATTERN, [] ):
            self.addPattern( pattern )


class _collector_19( _collector ):
    colId = HbsCollectorId.VOLUME_TRACKER

class _collector_20( _collector ):
    colId = HbsCollectorId.STATEFUL_TRACKING

class _collector_21( _collector ):
    colId = HbsCollectorId.USER_TRACKER

class _collector_22( _collector ):
    colId = HbsCollectorId.FILE_TYPE_TRACKER

    def init( self ):
        self.extensions = Set()

    def addExtension( self, ruleId, extension ):
        self.extensions.add( ( int( ruleId ), extension ) )

    def removeExtension( self, ruleId, extension ):
        self.extensions.remove( ( int( ruleId ), extension ) )

    def getProfile( self, root ):
        extList = rList()

        for ruleId, extension in self.extensions:
            extList.addSequence( _.base.RULE, rSequence().addInt8( _.base.RULE_NAME, ruleId )
                                                         .addStringA( _.base.EXTENSION, extension ) )

        root.addList( _.base.PATTERNS, extList )

        return root

    def putProfile( self, root ):
        for rule in root.get( _.base.PATTERNS, [] ):
            ruleId = rule.get( _.base.RULE_NAME, None )
            extension = rule.get( _.base.EXTENSION, None )
            if ruleId is not None and extension is not None:
                self.addExtension( ruleId, extension )


class SensorConfig( object ):
    def __init__( self ):
        self.collectors = [
            _collector_0(),
            _collector_1(),
            _collector_2(),
            _collector_3(),
            _collector_4(),
            _collector_5(),
            _collector_6(),
            _collector_7(),
            _collector_8(),
            _collector_9(),
            _collector_10(),
            _collector_11(),
            _collector_12(),
            _collector_13(),
            _collector_14(),
            _collector_15(),
            _collector_16(),
            _collector_17(),
            _collector_18(),
            _collector_19(),
            _collector_20(),
            _collector_21(),
            _collector_22(),
        ]

    def toProfile( self ):
        profile = rList()
        for col in self.collectors:
            profile.addSequence( _.hbs.CONFIGURATION, col.toProfile() )

        return profile

    def fromProfile( self, profile ):
        r = rpcm( isHumanReadable = False, isDebug = False, isDetailedDeserialize = False )
        r.setBuffer( profile )
        realProfile = r.deserialise( isList = True )
        if realProfile is not None:
            for colProfile in realProfile:
                colId = colProfile[ _.hbs.CONFIGURATION_ID ]
                if colId < len( self.collectors ):
                    self.collectors.fromProfile( colProfile )
            return True
        return False

    @classmethod
    def getDefaultWindowsProfile( cls ):
        profile = SensorConfig()
        profile.collectors[ 12 ].disable()
        profile.collectors[ 14 ].disable()
        profile.collectors[ HbsCollectorId.HIDDEN_MODULE ].disable()
        profile.collectors[ HbsCollectorId.EXEC_OOB ].disable()
        profile.collectors[ HbsCollectorId.PROCESS_HOLLOWING ].disable()
        profile.collectors[ HbsCollectorId.YARA ].disable()
        profile.collectors[ HbsCollectorId.STATEFUL_TRACKING ].disable()
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.NEW_PROCESS )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.TERMINATE_PROCESS )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.CODE_IDENTITY )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.DNS_REQUEST )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.HIDDEN_MODULE_DETECTED )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.NETWORK_SUMMARY )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_GET_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_DEL_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_MOV_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_HASH_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_INFO_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.DIR_LIST_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_MAP_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_READ_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_HANDLES_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_FIND_HANDLE_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_STRINGS_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_FIND_STRING_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_SERVICES_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_DRIVERS_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_KILL_PROCESS_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_SUSPEND_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_RESUME_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_PROCESSES_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_AUTORUNS_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.EXEC_OOB )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.GET_EXFIL_EVENT_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MODULE_MEM_DISK_MISMATCH )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.YARA_DETECTION )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.SERVICE_CHANGE )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.DRIVER_CHANGE )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.AUTORUN_CHANGE )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.NEW_DOCUMENT )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.GET_DOCUMENT_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.VOLUME_MOUNT )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.VOLUME_UNMOUNT )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.RECON_BURST )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.POSSIBLE_DOC_EXPLOIT )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.HISTORY_DUMP_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.USER_OBSERVED )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_TYPE_ACCESSED )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.EXISTING_PROCESS )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.SELF_TEST_RESULT )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].addExtension( 1, ".doc" )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].addExtension( 1, ".docm" )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].addExtension( 1, ".docx" )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].addExtension( 2, ".xlt" )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].addExtension( 2, ".xlsm" )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].addExtension( 2, ".xlsx" )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].addExtension( 3, ".ppt" )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].addExtension( 3, ".pptm" )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].addExtension( 3, ".pptx" )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].addExtension( 3, ".ppts" )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].addExtension( 4, ".pdf" )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].addExtension( 5, ".rtf" )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].addExtension( 50, ".zip" )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].addExtension( 51, ".rar" )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].addExtension( 64, ".locky" )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].addExtension( 64, ".aesir" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".bat" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".js" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".ps1" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".sh" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".py" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".exe" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".scr" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".pdf" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".doc" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".docm" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".docx" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".ppt" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".pptm" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".pptx" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".xlt" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".xlsm" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".xlsx" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".vbs" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".rtf" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addExtension( ".hta" )
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].addPattern( "\\windows\\system32\\" )
        profile.collectors[ HbsCollectorId.FILE_TRACKER ].disableModified()

        return profile

    @classmethod
    def getDefaultOsxProfile( cls ):
        profile = SensorConfig()
        profile.collectors[ 12 ].disable()
        profile.collectors[ 14 ].disable()
        profile.collectors[ HbsCollectorId.HIDDEN_MODULE ].disable()
        profile.collectors[ HbsCollectorId.EXEC_OOB ].disable()
        profile.collectors[ HbsCollectorId.PROCESS_HOLLOWING ].disable()
        profile.collectors[ HbsCollectorId.YARA ].disable()
        profile.collectors[ HbsCollectorId.STATEFUL_TRACKING ].disable()
        profile.collectors[ HbsCollectorId.MODULE_TRACKER ].disable()
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.NEW_PROCESS )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.TERMINATE_PROCESS )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.CODE_IDENTITY )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.DNS_REQUEST )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.HIDDEN_MODULE_DETECTED )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.NETWORK_SUMMARY )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_GET_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_DEL_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_MOV_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_HASH_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_INFO_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.DIR_LIST_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_MAP_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_READ_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_HANDLES_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_FIND_HANDLE_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_STRINGS_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_FIND_STRING_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_SERVICES_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_DRIVERS_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_KILL_PROCESS_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_SUSPEND_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_RESUME_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_PROCESSES_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_AUTORUNS_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.EXEC_OOB )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.GET_EXFIL_EVENT_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MODULE_MEM_DISK_MISMATCH )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.YARA_DETECTION )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.SERVICE_CHANGE )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.DRIVER_CHANGE )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.AUTORUN_CHANGE )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.NEW_DOCUMENT )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.GET_DOCUMENT_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.VOLUME_MOUNT )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.VOLUME_UNMOUNT )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.RECON_BURST )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.POSSIBLE_DOC_EXPLOIT )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.HISTORY_DUMP_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.USER_OBSERVED )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_TYPE_ACCESSED )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.EXISTING_PROCESS )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.SELF_TEST_RESULT )
        profile.collectors[ HbsCollectorId.FILE_TRACKER ].disableModified()

        return profile

    @classmethod
    def getDefaultLinuxProfile( cls ):
        profile = SensorConfig()
        profile.collectors[ 12 ].disable()
        profile.collectors[ 14 ].disable()
        profile.collectors[ HbsCollectorId.HIDDEN_MODULE ].disable()
        profile.collectors[ HbsCollectorId.EXEC_OOB ].disable()
        profile.collectors[ HbsCollectorId.PROCESS_HOLLOWING ].disable()
        profile.collectors[ HbsCollectorId.YARA ].disable()
        profile.collectors[ HbsCollectorId.STATEFUL_TRACKING ].disable()
        profile.collectors[ HbsCollectorId.MODULE_TRACKER ].disable()
        profile.collectors[ HbsCollectorId.DNS_TRACKER ].disable()
        profile.collectors[ HbsCollectorId.NETWORK_TRACKER ].disable()
        profile.collectors[ HbsCollectorId.FILE_TRACKER ].disable()
        profile.collectors[ HbsCollectorId.DOC_COLLECTOR ].disable()
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.NEW_PROCESS )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.TERMINATE_PROCESS )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.CODE_IDENTITY )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.DNS_REQUEST )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.HIDDEN_MODULE_DETECTED )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.NETWORK_SUMMARY )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_GET_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_DEL_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_MOV_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_HASH_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_INFO_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.DIR_LIST_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_MAP_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_READ_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_HANDLES_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_FIND_HANDLE_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_STRINGS_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MEM_FIND_STRING_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_SERVICES_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_DRIVERS_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_KILL_PROCESS_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_SUSPEND_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_RESUME_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_PROCESSES_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.OS_AUTORUNS_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.EXEC_OOB )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.GET_EXFIL_EVENT_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.MODULE_MEM_DISK_MISMATCH )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.YARA_DETECTION )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.SERVICE_CHANGE )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.DRIVER_CHANGE )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.AUTORUN_CHANGE )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.NEW_DOCUMENT )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.GET_DOCUMENT_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.VOLUME_MOUNT )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.VOLUME_UNMOUNT )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.RECON_BURST )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.POSSIBLE_DOC_EXPLOIT )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.HISTORY_DUMP_REP )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.USER_OBSERVED )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.FILE_TYPE_ACCESSED )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.EXISTING_PROCESS )
        profile.collectors[ HbsCollectorId.EXFIL ].addExfil( _.notification.SELF_TEST_RESULT )
        profile.collectors[ HbsCollectorId.FILE_TYPE_TRACKER ].disable()

        return profile