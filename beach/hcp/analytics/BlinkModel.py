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
import time
from sets import Set
import uuid
import json
import tld
import tld.utils
BEAdmin = Actor.importLib( '../admin_lib', 'BEAdmin' )
EventInterpreter = Actor.importLib( '../utils/EventInterpreter', 'EventInterpreter' )
Host = Actor.importLib( '../utils/ObjectsDb', 'Host' )
HostObjects = Actor.importLib( '../utils/ObjectsDb', 'HostObjects' )
FluxEvent = Actor.importLib( '../utils/ObjectsDb', 'FluxEvent' )
ObjectTypes = Actor.importLib( '../utils/ObjectsDb', 'ObjectTypes' )
Atoms = Actor.importLib( '../utils/ObjectsDb', 'Atoms' )
ObjectKey = Actor.importLib( '../utils/ObjectsDb', 'ObjectKey' )
RelationNameFromId = Actor.importLib( '../utils/ObjectsDb', 'RelationNameFromId' )
ObjectNormalForm = Actor.importLib( '../utils/ObjectsDb', 'ObjectNormalForm' )
KeyValueStore = Actor.importLib( '../utils/ObjectsDb', 'KeyValueStore' )
AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )
_xm_ = Actor.importLib( '../utils/hcp_helpers', '_xm_' )
_x_ = Actor.importLib( '../utils/hcp_helpers', '_x_' )

class BlinkModel( Actor ):
    def init( self, parameters, resources ):
        self.admin = BEAdmin( self._beach_config_path, None )
        Host.setDatabase( self.admin, parameters[ 'scale_db' ] )
        HostObjects.setDatabase( parameters[ 'scale_db' ] )
        KeyValueStore.setDatabase( parameters[ 'scale_db' ] )
        Atoms.setDatabase( parameters[ 'scale_db' ] )
        self.alexa = {}
        self.refreshAlexa()
        self.handle( 'get_host_blink', self.get_host_blink )

    def deinit( self ):
        Host.closeDatabase()
        HostObjects.closeDatabase()

    def refreshAlexa( self ):
        alexaActor = self.getActorHandle( 'analytics/alexadns' )
        info = alexaActor.request( 'get_list', {} )
        if info.isSuccess:
            i = 0
            newAlexa = {}
            for domain in info.data[ 'domains' ]:
                i += 1
                newAlexa[ domain ] = i
            self.alexa = newAlexa

        try:
            tld.update_tld_names()
        except:
            pass

        self.delay( 60 * 60 * 24, self.refreshAlexa )

    def getAlexaTag( self, domain ):
        if domain is None: return None
        if len( self.alexa ) == 0: return None
        try:
            domain = tld.get_tld( domain, fix_protocol = True )
        except:
            pass
        position = self.alexa.get( domain, None )
        if position is None:
            tag = '-ALEXA'
        elif position <= 1000:
            tag = '+ALEXA/%s' % position
        else:
            tag = '?ALEXA/%s' % position
        return tag

    def getVtReportTag( self, h ):
        tag = None
        if h is None: return None
        if not all( x in "1234567890abcdef" for x in h.lower() ) and len( h ) in [ 32, 40, 64 ]:
            h = h.encode( 'hex' )
        h = h.lower()
        report = KeyValueStore.getKey( 'vt', h )
        if report is not None:
            report = json.loads( report[ 0 ] )
            hits = 0
            for av, r in report.iteritems():
                if r is not None:
                    hits += 1
            if hits > 2:
                tag = '-VT/%s' % hits
            else:
                tag = '?VT/%s' % hits
        return tag

    def getObjKey( self, objname, objtype, isCaseSensitive ):
        if objname is None or objtype is None: return None
        return ObjectKey( ObjectNormalForm( objname, objtype, isCaseSensitive = isCaseSensitive ), objtype )

    def getObjFrequencyTag( self, aid, objname, objtype ):
        k = self.getObjKey( objname, objtype, isCaseSensitive = not aid.isWindows() )
        if k is None: return None
        nLocs = len( [ _ for _ in HostObjects( k ).locs() ] )
        if nLocs <= 1:
            tag = '-LOC/%s' % nLocs
        elif nLocs > 20:
            tag = '+LOC/%s' % nLocs
        else:
            tag = '?LOC/%s' % nLocs
        return tag

    def get_host_blink( self, msg ):
        aid = AgentId( msg.data[ 'aid' ] )
        after = msg.data[ 'after' ]
        before = msg.data[ 'before' ]

        blink = []

        host = Host( aid.sensor_id )

        events = host.getEvents( before = before,
                                 after = after,
                                 limit = None,
                                 ofTypes = None,
                                 isIncludeContent = True )

        interpreter = EventInterpreter()

        # Record format
        # 0 : THIS_ATOM
        # 1 : PARENT_ATOM
        # 2 : KEY
        # 3 : Set(TAGS)
        # 4 : TIME

        ofInterest = Set( ( 'notification.NEW_PROCESS',
                            'notification.CODE_IDENTITY',
                            'notification.DNS_REQUEST',
                            'notification.MODULE_LOAD' ) )

        for event in events:
            if event[ 1 ] not in ofInterest: continue

            record = []
            eventData = FluxEvent.decode( event[ 3 ], withRouting = False )
            interpreter.setEvent( eventData )
            key = interpreter.key()
            eventType = interpreter.name()
            record.append( interpreter.getAtom() )
            record.append( interpreter.getParentAtom() )
            record.append( '%s - %s' % ( eventType, key ) )

            tags = []
            if 'NEW_PROCESS' == eventType:
                tag = self.getObjFrequencyTag( aid, *interpreter.object() )
                if tag is not None:
                    tags.append( tag )
            elif 'CODE_IDENTITY' == eventType:
                tag = self.getVtReportTag( interpreter.object()[ 0 ] )
                if tag is not None:
                    tags.append( tag )
                tag = self.getObjFrequencyTag( aid, *interpreter.object() )
                if tag is not None:
                    tags.append( tag )
            elif 'DNS_REQUEST' == eventType:
                tag = self.getObjFrequencyTag( aid, *interpreter.object() )
                if tag is not None:
                    tags.append( tag )
                tag = self.getAlexaTag( interpreter.object()[ 0 ] )
                if tag is not None:
                    tags.append( tag )
            elif 'MODULE_LOAD' == eventType:
                tag = self.getObjFrequencyTag( aid, *interpreter.object() )
                if tag is not None:
                    tags.append( tag )

            record.append( tags )
            record.append( event[ 0 ] )

            blink.append( record )


        return ( True, { 'blink' : blink } )
