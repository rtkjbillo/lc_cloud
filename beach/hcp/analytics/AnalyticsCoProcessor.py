# Copyright 2017 Google, Inc
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
from beach.utils import loadModuleFrom
import traceback
import json
import uuid
import time
import msgpack
import base64
EventDSL = Actor.importLib( '../utils/EventInterpreter', 'EventDSL' )
AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )
StateMachine = Actor.importLib( '../analytics/StateAnalysis', 'StateMachine' )
_StateMachineContext = Actor.importLib( '../analytics/StateAnalysis', '_StateMachineContext' )
StateEvent = Actor.importLib( '../analytics/StateAnalysis', 'StateEvent' )
HostObjects = Actor.importLib( '../utils/ObjectsDb', 'HostObjects' )
KeyValueStore = Actor.importLib( '../utils/ObjectsDb', 'KeyValueStore' )
Atoms = Actor.importLib( '../utils/ObjectsDb', 'Atoms' )

class SensorContext( object ):
    __slots__ = [ '_actor', 'aid', 'routing' ]

    def __init__( self, fromActor, routing ):
        self._actor = fromActor
        self.aid = AgentId( routing[ 'aid' ] )
        self.routing = routing

    def task( self, cmdsAndArgs, expiry = None, inv_id = None ):
        '''Send a task manually to a sensor

        :param cmdAndArgs: tuple of arguments (like the CLI) of the task
        :param expiry: number of seconds before the task is not valid anymore
        :param inv_id: investigation id to associate the tasking and reply to
        '''

        self._actor.log( "sent for tasking: %s" % ( str( cmdsAndArgs ), ) )
        dest = str( self.aid )
        if type( cmdsAndArgs[ 0 ] ) not in ( tuple, list ):
            cmdsAndArgs = ( cmdsAndArgs, )
        data = { 'dest' : dest, 'tasks' : cmdsAndArgs }

        if expiry is not None:
            data[ 'expiry' ] = expiry
        if inv_id is not None:
            data[ 'inv_id' ] = inv_id

        self._actor.tasking.shoot( 'task', data, key = dest )
        return True

    def tag( self, tag, ttl = ( 60 * 60 * 24 * 365 ) ):
        if not self.isTagged( tag ):
            self._actor.log( "sent for tagging: %s" % tag )
            self._actor.tagging.shoot( 'add_tags', 
                                       { 'tag' : tag, 
                                         'ttl' : ttl, 
                                         'sid' : self.aid.sensor_id, 
                                         'by' : 'AnalyticsCoProcessor' } )
        return True

    def untag( self, tag, ttl = ( 60 * 60 * 24 * 365 ) ):
        if not self.isTagged( tag ):
            self._actor.log( "sent for untagging: %s" % tag )
            self._actor.tagging.shoot( 'del_tags', 
                                       { 'tag' : tag, 
                                         'ttl' : ttl, 
                                         'sid' : self.aid.sensor_id, 
                                         'by' : 'AnalyticsCoProcessor' } )
        return True

    def isTagged( self, tag ):
        return tag.lower() in self.routing[ 'tags' ]

    def inOrg( self, oid ):
        return str( oid ) == str( self.aid.org_id )


class AnalyticsCoProcessor( object ):
    def init( self, parameters, resources, fromActor ):
        self._actor = fromActor
        self.rules = {}

        HostObjects.setDatabase( self._actor.db )
        KeyValueStore.setDatabase( self._actor.db )
        Atoms.setDatabase( self._actor.db )

        self.statefulDescriptors = {}
        self.statefulInstances = {}
        self.stateful_loadStatement = self._actor.db.prepare( 'SELECT state_data FROM stateful_states WHERE sid = ?' )
        self.stateful_saveStatement = self._actor.db.prepare( 'INSERT INTO stateful_states ( sid, state_data ) VALUES ( ?, ? ) USING TTL ?' )
        self.statefulTtl = ( 60 * 60 * 24 * 30 )

        self.deploymentmanager = self._actor.getActorHandle( resources[ 'deployment' ], nRetries = 3, timeout = 30 )
        self.models = self._actor.getActorHandle( resources[ 'modeling' ], timeout = 30, nRetries = 3 )
        self.tagging = self._actor.getActorHandle( resources[ 'tagging' ], timeout = 30, nRetries = 3 )
        self.reporting = self._actor.getActorHandle( resources[ 'reporting' ], timeout = 30, nRetries = 3 )
        self.paging = self._actor.getActorHandle( resources[ 'paging' ], timeout = 60, nRetries = 3 )
        self.tasking = self._actor.getActorHandle( resources[ 'autotasking' ], 
                                             mode = 'affinity',
                                             timeout = 60,
                                             nRetries = 2 )

        self.conf = {}
        self.reloadRules( None )
        self._actor.schedule( 60 * 60, self.reloadRules, None )

        self.invTtl = parameters.get( 'inv_ttl', 60 * 60 * 24 )
        self.handleCache = {}
        self.handleTtl = {}
        self._actor.schedule( 60, self.invCulling )

        self._actor.handle( 'add_rule', self.addRule )
        self._actor.handle( 'del_rule', self.delRule )
        self._actor.handle( 'get_rules', self.getRules )
        self._actor.handle( 'reload_rules', self.reloadRules )

        return self

    def deinit( self ):
        pass

    def onSensorConnected( self, client ):
        row = self._actor.db.getOne( self.stateful_loadStatement.bind( ( client.aid.sensor_id, ) ) )
        if row is None:
            return
        shard = str( client.aid.sensor_id )
        stateMap = msgpack.unpackb( row[ 0 ] )
        self._actor.log( "Restoring %s rule sets for client %s" % ( len( stateMap ), shard ) )
        nDiscarded = 0
        nLoaded = 0
        for ruleName, instances in stateMap.iteritems():
            desc = self.statefulDescriptors.get( ruleName, None )
            if desc is None:
                nDiscarded += 1
                continue
            desc = desc._descriptor
            self.statefulInstances.setdefault( ruleName, {} ).setdefault( shard, [] )
            for instance in instances:
                self.statefulInstances[ ruleName ][ shard ].append( _StateMachineContext( desc ).restoreState( instance ) )
                nLoaded += 1
        if 0 != nLoaded or 0 != nDiscarded:
            self._actor.log( "Loaded %s states and discarded %s." % ( nLoaded, nDiscarded ) )

    def onSensorDisconnected( self, client ):
        shard = str( client.aid.sensor_id )
        stateMap = {}
        for ruleName, instanceMap in self.statefulInstances.items():
            instances = instanceMap.pop( shard, None )
            if instances is not None:
                stateMap[ ruleName ] = []
                for instance in instances:
                    stateMap[ ruleName ].append( instance.saveState() )
        self._actor.log( "Saving %s rule states for client %s" % ( len( stateMap ), shard ) )
        if 0 == len( stateMap ):
            return
        stateMap = msgpack.packb( stateMap )
        self._actor.db.execute( self.stateful_saveStatement.bind( ( client.aid.sensor_id, stateMap, self.statefulTtl ) ) )

    def page( self, to = None, subject = None, data = None ):
        if to is None: 
            return False

        if type( data ) is EventDSL:
            data = data.asJSON()

        resp = self.paging.request( 'page', { 'to' : to, 
                                              'subject' : subject, 
                                              'msg' : json.dumps( data, indent = 2 ) } )

        if not resp.isSuccess:
            self._actor.log( "Failed to page: %s" % str( resp ) )

        return resp.isSuccess

    def massageUrl( self, url ):
        if url.startswith( 'https://github.com/' ):
            url = url.replace( 'https://github.com/', 'https://raw.githubusercontent.com/' ).replace( '/blob/', '/' )
        return url

    def compileRule( self, ruleRecord ):
        env = { 'False' : False, 
                'True' : True }
        env[ "__name__" ] = None
        env[ "__file__" ] = None
        env[ "__builtins__" ] = None

        try:
            rule = {
                'name' : ruleRecord[ 'name' ], 
                'original' : ruleRecord[ 'rule' ],
            }

            if '://' in ruleRecord[ 'rule' ]:
                url = self.massageUrl( ruleRecord[ 'rule' ] )
                className = ruleRecord[ 'rule' ].split( '/' )[ -1 ]
                if className.endswith( '.py' ):
                    className = className[ 0 : -3 ]
                newClass = getattr( loadModuleFrom( url, 'hcp' ),
                                    className )
                newObj = newClass( self._actor )
                if hasattr( newObj, 'analyze' ):
                    cb = newObj.analyze
                elif hasattr( newObj, 'getDescriptor' ):
                    self.statefulDescriptors[ ruleRecord[ 'name' ] ] = StateMachine( descriptor = newObj.getDescriptor() )
                    self.statefulInstances[ ruleRecord[ 'name' ] ] = {}
                    cb = lambda event, sensor: self.evalStateful( ruleRecord[ 'name' ], event, sensor )
                else:
                    raise Exception( 'unknown file format, missing "analyze" export.' )
                rule[ 'rule' ] = cb
            else:
                rule[ 'rule' ] = eval( 'lambda event, sensor: ( %s )' % ( ruleRecord[ 'rule' ], ), env, env )


            if '://' in ruleRecord[ 'action' ]:
                url = self.massageUrl( ruleRecord[ 'action' ] )
                className = ruleRecord[ 'rule' ].split( '/' )[ -1 ]
                if className.endswith( '.py' ):
                    className = className[ 0 : -3 ]
                newClass = getattr( loadModuleFrom( url, 'hcp' ),
                                    className )
                newObj = newClass( self._actor )
                if hasattr( newObj, 'respond' ):
                    cb = newObj.respond
                else:
                    raise Exception( 'unknown file format, missing "respond" export.' )
                rule[ 'action' ] = cb
            else:
                rule[ 'action' ] = eval( 'lambda event, sensor, context, report, page: ( %s )' % ( ruleRecord[ 'action' ], ), env, env )

            # Test to see if a dummy call to the match and action will result in True
            # this should never occur and is an indicator of a bad rule that always triggers.
            isBad = False
            try:
                if rule[ 'rule' ]( None, None ):
                    isBad = True
            except:
                pass

            if isBad:
                raise Exception( 'matching rule invalid, always returns True' )

            return ( rule, None )
        except:
            exc = traceback.format_exc()
            self._actor.log( "Error compiling rule %s: %s" % ( ruleRecord.get( 'name', '-' ), exc ) )
            return ( None, exc )

    def saveRules( self ):
        resp = self.deploymentmanager.request( 'set_config', { 'conf' : 'global/quick_detects', 
                                                               'value' : json.dumps( self.conf ), 
                                                               'by' : 'AnalyticsCoProcessor' } )
        return resp.isSuccess

    def addRule( self, msg ):
        req = msg.data
        name = req[ 'name' ]
        rule = req[ 'rule' ]
        action = req[ 'action' ]
        by = req[ 'by' ]
        if name in self.rules:
            return ( False, 'rule already exists' )

        compiled, exc  = self.compileRule( req )
        if compiled is None:
            return ( False, exc )
        self.rules[ name ] = compiled
        self.conf[ name ] = { 'name' : name, 'rule' : rule, 'action' : action, 'by' : by, 'date' : int( time.time() ) }

        return ( self.saveRules(), )

    def delRule( self, msg ):
        req = msg.data
        name = req[ 'name' ]
        if name not in self.rules:
            return ( False, 'rule not found' )
        self.rules.pop( name, None )
        self.conf.pop( name, None )
        self._actor.log( "Removed rule %s." % name )
        return ( self.saveRules(), )

    def evalStateful( self, ruleName, event, sensor ):
        isMatch = False
        matchContent = None
        
        newEvent = StateEvent( sensor.routing, event.data, event.mtd )
        shard = str( sensor.aid.sensor_id )
        machines = self.statefulInstances[ ruleName ].setdefault( shard, [] )
        
        # First run the event through all the machines already running.
        for machine in machines[:]:
            reportContent, isStayAlive = machine.update( newEvent )
            if reportContent is not None:
                isMatch = True
                matchContent = reportContent
                # We don't break since we have to update all the machines.
            if not isStayAlive:
                machines.remove( machine )

        # Now prime a new machine to see if it's a hit.
        newMachine = self.statefulDescriptors[ ruleName ].prime( newEvent )
        if newMachine is not None:
            self.statefulInstances[ ruleName ][ shard ].append( newMachine )

        return isMatch, matchContent

    def checkRule( self, rule, event, sensor ):
        try:
            result = rule[ 'rule' ]( event, sensor )
            context = None
            if type( result ) is tuple:
                result, context = result
            if result:
                def report( name = None, content = None, priority = 0, isPublish = True ):
                    if name is None:
                        return False

                    rep = { 'source' : sensor.aid, 
                            'msg_ids' : sensor.routing[ 'event_id' ], 
                            'cat' : name, 
                            'detect' : content or event.data, 
                            'detect_id' : uuid.uuid4(), 
                            'summary' : 'detect: %s' % rule[ 'original' ],
                            'priority' : priority }

                    # Create a new somewhat special EventDSL that representa the detection.
                    detection = EventDSL( { 'detection_%s' % name : content or event.data }, 
                                          { 'obj' : {}, 'rel' : {} }, 
                                          not sensor.aid.isWindows() )
                    self._actor.delay( 0, 
                                       self._actor.parallelExec, 
                                       lambda rule: self.checkRule( rule, detection, sensor ), 
                                       self.rules.values() )

                    if isPublish:
                        resp = self.reporting.request( 'detect', rep )

                        if not resp.isSuccess:
                            self._actor.log( "Failed to report: %s" % str( resp ) )

                        return resp.isSuccess
                    else:
                        return True
                self._actor.zInc( 'detections.%s' % rule[ 'name' ] )
                self._actor.log( "!!! Rule %s matched: %s." % ( rule[ 'name' ], context ) )
                rule[ 'action' ]( event, sensor, context, report, self.page )
        except:
            self._actor.log( "Error evaluating %s: %s" % ( rule[ 'name' ], traceback.format_exc() ) )
            self._actor.zInc( 'error.%s' % rule[ 'name' ] )

    def getRules( self, msg ):
        return ( True, self.conf )

    def reloadRules( self, msg ):
        self._actor.log( "Fetching detection rules." )
        resp = self.deploymentmanager.request( 'get_quick_detects', {} )
        conf = {}
        rules = {}
        errors = []
        if resp.isSuccess:
            try:
                conf = json.loads( resp.data[ 'detects' ] )
                self._actor.log( "Found %d detect rules." % len( conf ) )
            except:
                errors.append( traceback.format_exc() )
                conf = {}
        else:
            self._actor.log( "No detection rules found." )

        for name, ruleInfo in conf.items():
            compiled, exc  = self.compileRule( ruleInfo )
            if compiled is None:
                errors.append( exc )
            else:
                rules[ name ] = compiled

        self.rules = rules
        self.conf = conf

        # Remove stateful states relating to rules that no
        # longer exist.
        for ruleName in self.statefulInstances.keys():
            if ruleName not in self.rules:
                self.statefulInstances.pop( ruleName, None )

        if 0 != len( errors ):
            return ( False, errors )

        self._actor.zSet( 'n_rules', len( self.conf ) )

        return ( True, )

    def analyze( self, routing, event, mtd ):
        if 0 == len( self.rules ):
            return True

        sensor = SensorContext( self._actor, routing )
        tmpEvent = EventDSL( event, mtd, not sensor.aid.isWindows() )
        self._actor.parallelExec( lambda rule: self.checkRule( rule, tmpEvent, sensor ), self.rules.values() )

        self._actor.zInc( 'analyzed' )

        return True

    def invCulling( self ):
        curTime = int( time.time() )
        inv_ids = [ inv_id for inv_id, ts in self.handleTtl.iteritems() if ts < ( curTime - self.invTtl ) ]
        for inv_id in inv_ids:
            self.handleCache[ inv_id ].close()
            del( self.handleCache[ inv_id ] )
            del( self.handleTtl[ inv_id ] )

    def forwardInvestigations( self, routing, event, mtd ):
        inv_id = routing.get( 'investigation_id', None )

        if inv_id is None:
            return

        # We define the component after the // to be reserved for
        # the actor's internal routing so we don't route on it.
        routing_inv_id = inv_id.split( '//' )[ 0 ]

        now = int( time.time() )

        if routing_inv_id not in self.handleCache:
            handle = self.getActorHandle( self.invPath % routing_inv_id, timeout = 30, nRetries = 2 )
            self.handleCache[ routing_inv_id ] = handle
            self.handleTtl[ routing_inv_id ] = now
        else:
            handle = self.handleCache[ routing_inv_id ]
            self.handleTtl[ routing_inv_id ] = now

        # Sometimes we're just too fast, so if we don't see a subscriber
        # wait a bit to give it a chance.
        if not handle.isAvailable():
            self.sleep( 2 )
            handle.forceRefresh()

        self.log( 'investigation data going to: %d' % handle.getNumAvailable() )
        # The investigation id is used as a requestType since most actors
        # who need to be registered to investigations also need to
        # multiplex several investigations so if we do the differentiation
        # at that level we don't need to maintain a local registration
        # list on every actor.
        handle.broadcast( inv_id, ( routing, event, mtd ) )