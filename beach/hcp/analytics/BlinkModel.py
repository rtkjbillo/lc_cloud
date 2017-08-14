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
import json
import tld
import tld.utils
import itertools
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
chunks = Actor.importLib( '../utils/hcp_helpers', 'chunks' )

class BlinkModel( Actor ):
    def init( self, parameters, resources ):
        self.admin = BEAdmin( self._beach_config_path, None )
        Host.setDatabase( self.admin, parameters[ 'scale_db' ] )
        HostObjects.setDatabase( parameters[ 'scale_db' ] )
        KeyValueStore.setDatabase( parameters[ 'scale_db' ] )
        Atoms.setDatabase( parameters[ 'scale_db' ] )
        self.alexa = {}
        self.malwaredomains = {}
        self.refreshAlexa()
        self.refreshMalwareDomains()
        self.scopers = {
            "DOMAIN_NAME" : self.scopeDomainName,
        }
        self.handle( 'get_host_blink', self.get_host_blink )
        self.handle( 'scope_this', self.scope_this )

    def deinit( self ):
        Host.closeDatabase()
        HostObjects.closeDatabase()

    def refreshAlexa( self ):
        alexaActor = self.getActorHandle( 'analytics/alexadns' )
        try:
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
        except:
            raise
        finally:
            alexaActor.close()

    def refreshMalwareDomains( self ):
        mdActor = self.getActorHandle( 'analytics/malwaredomains' )
        try:
            info = mdActor.request( 'get_list', {} )
            if info.isSuccess:
                self.malwaredomains = info.data[ 'domains' ]

            self.delay( 60 * 60 * 24, self.refreshMalwareDomains )
        except:
            raise
        finally:
            mdActor.close()

    def getAlexaTag( self, domain ):
        if domain is None: return None
        if len( self.alexa ) == 0: return None
        try:
            domain = tld.get_tld( domain, fix_protocol = True )
        except:
            pass
        position = self.alexa.get( domain, None )
        if position is None:
            tag = '-ALEXA/'
        elif position <= 1000:
            tag = '+ALEXA/%s' % position
        else:
            tag = '?ALEXA/%s' % position
        return tag

    def getMalwareDomainsTag( self, domain ):
        if domain is None: return None
        if len( self.malwaredomains ) == 0: return None

        if self.malwaredomains.get( domain, None ) is not None:
            tag = '-MALWAREDOMAINS/'
        else:
            tag = '?MALWAREDOMAINS/'
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
            elif hits == 0:
                tag = '+VT/%s' % hits
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
                tag = self.getMalwareDomainsTag( interpreter.object()[ 0 ] )
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

    def _getEventsForObject( self, objId, acl ):
        def thisGen():
            for eInfo in chunks( HostObjects( objId ).acl( acl ).events(), 20 ):
                for eid, sid, event in Host.getSpecificEvents( x[ 2 ] for x in eInfo ):
                    r, d = FluxEvent.decode( event, withRouting = True )
                    yield ( r, EventInterpreter( d ) )
        return thisGen()

    def scope_this( self, msg ):
        acl = msg.data.get( 'oid', None )
        seedObjType = msg.data[ 'obj_type' ]
        seedObjName = msg.data[ 'obj_name' ]
        
        crumbs = [ ScopeCrumb( seedObjName, seedObjType, 'source object', None ) ]
        uniqueCrumbs = Set()
        atoms = Set()
        for crumb in crumbs:
            handler = self.scopers.get( crumb.oType, None )
            if handler is None: continue
            newCrumbs, newAtoms = handler( crumb, acl )
            for newCrumb in newCrumbs:
                if newCrumb.oId not in uniqueCrumbs:
                    uniqueCrumbs.add( newCrumb.oId )
                    crumbs.append( newCrumb )
            atoms.update( newAtoms )

        return ( True, { 'scope' : map( lambda x: x.toJson(), crumbs ) } )

    def scopeDomainName( self, crumb, acl ):
        newCrumbs = []
        newAtoms = Set()

        for routing, iEvent in self._getEventsForObject( crumb.oId, acl ):
            ts = iEvent.getTimestamp() / 1000
            h = Host( routing[ 'aid' ] )
            domain = _x_( iEvent.event, '*/base.DOMAIN_NAME' )
            ip = _x_( iEvent.event, '*/base.IP_ADDRESS' )

            if ip is not None:
                newCrumbs.append( ScopeCrumb( ip, 'IP_ADDRESS', 'domain %s resolved to ip' % crumb.oName, iEvent.getAtom() ) )

            # Get all DNS requests and connections around the event.
            dnsRequests = h.getEvents( ofTypes = 'notification.DNS_REQUEST', after = ts - ( 30 ), before = ts + ( 30 ), isIncludeContent = True )
            

            # Try to see what other resolutions are related to this one.
            for eTime, eType, eId, eContent in dnsRequests:
                eRouting, eData = FluxEvent.decode( eContent, withRouting = True )
                cName = _x_( eData, '?/base.CNAME' )
                domainName = _x_( eData, '?/base.DOMAIN_NAME' )
                ipAddress = _x_( eData, '?/base.IP_ADDRESS' )
                newAtoms.add( EventInterpreter( eData ).getAtom() )
                if domainName == crumb.oName and cName is not None:
                    newCrumbs.append( ScopeCrumb( cName, 'DOMAIN_NAME', 'cname resolution of %s' % crumb.oName, EventInterpreter( eData ).getAtom() ) )
                elif cName == crumb.oName:
                    newCrumbs.append( ScopeCrumb( domainName, 'DOMAIN_NAME', 'cname resolution to %s' % crumb.oName, EventInterpreter( eData ).getAtom() ) )
                #TODO: make it loop until any and all relevant cname chains have been fully resolved.

            dnsRequests = None

            # Get all network activity and connections around the event.
            newConnections = h.getEvents( ofTypes = ( 'notification.NEW_TCP4_CONNECTION', 
                                                      'notification.NEW_UDP4_CONNECTION',
                                                      'notification.NEW_TCP6_CONNECTION',
                                                      'notification.NEW_UDP6_CONNECTION' ), 
                                          after = ts - 1, before = ts + ( 30 ), isIncludeContent = True )
            newSummaries = h.getEvents( ofTypes = 'notification.NETWORK_SUMMARY', after = ts - ( 1 ), before = ts + ( 60 * 5 ), isIncludeContent = True )

            # Try to see who made a connection to the resulting IPs afterward.
            for eTime, eType, eId, eContent in itertools.chain( newConnections, newSummaries ):
                eRouting, eData = FluxEvent.decode( eContent, withRouting = True )
                ips = _xm_( eData, '*/base.IP_ADDRESS' )
                if ip in ips:
                    newAtoms.add( EventInterpreter( eData ).getAtom() )

            newConnections = None
            newSummaries = None

        return newCrumbs, newAtoms

class ScopeCrumb( object ):
    def __init__( self, objName, objType, why, srcAtom ):
        self.oName = objName
        self.oType = objType
        self.oId = ObjectKey( ObjectNormalForm( self.oName, self.oType ), self.oType )
        self.why = why
        self.atom = srcAtom

    def toJson( self ):
        return { 'oName' : self.oName, 'oType' : self.oType, 'oId' : self.oId, 'why' : self.why, 'atom' : self.atom }