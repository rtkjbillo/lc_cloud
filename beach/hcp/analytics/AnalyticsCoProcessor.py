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
EventDSL = Actor.importLib( '../utils/EventInterpreter', 'EventDSL' )
AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )

class SensorContext( object ):
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
                                         'by' : 'QuickDetectHost' } )
        return True

    def untag( self, tag, ttl = ( 60 * 60 * 24 * 365 ) ):
        if not self.isTagged( tag ):
            self._actor.log( "sent for untagging: %s" % tag )
            self._actor.tagging.shoot( 'del_tags', 
                                       { 'tag' : tag, 
                                         'ttl' : ttl, 
                                         'sid' : self.aid.sensor_id, 
                                         'by' : 'QuickDetectHost' } )
        return True

    def isTagged( self, tag ):
        return tag.lower() in self.routing[ 'tags' ]

    def inOrg( self, oid ):
        return str( oid ) == str( self.aid.org_id )


class AnalyticsCoProcessor( object ):
    def init( self, parameters, resources, fromActor ):
        self._actor = fromActor
        self.rules = {}

        self.deploymentmanager = self._actor.getActorHandle( resources[ 'deployment' ], nRetries = 3, timeout = 30 )
        self.models = self._actor.getActorHandle( resources[ 'modeling' ], timeout = 30, nRetries = 3 )
        self.tagging = self._actor.getActorHandle( resources[ 'tagging' ], timeout = 30, nRetries = 3 )
        self.reporting = self._actor.getActorHandle( resources[ 'reporting' ], timeout = 30, nRetries = 3 )
        self.paging = self._actor.getActorHandle( resources[ 'paging' ], timeout = 60, nRetries = 3 )
        self.tasking = self._actor.getActorHandle( resources[ 'autotasking' ], 
                                             mode = 'affinity',
                                             timeout = 60,
                                             nRetries = 2 )
        self.stateful = self._actor.getActorHandle( resources[ 'stateful' ], timeout = 60, nRetries = 3 )

        self.conf = {}
        self.reloadRules( None )
        self._actor.schedule( 60 * 60, self.reloadRules, None )

        self._actor.handle( 'add_rule', self.addRule )
        self._actor.handle( 'del_rule', self.delRule )
        self._actor.handle( 'get_rules', self.getRules )
        self._actor.handle( 'reload_rules', self.reloadRules )

        return self

    def deinit( self ):
        pass

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

    def compileRule( self, rule ):
        env = { 'False' : False, 
                'True' : True }
        env[ "__name__" ] = None
        env[ "__file__" ] = None
        env[ "__builtins__" ] = None

        try:
            if '://' in rule[ 'rule' ]:
                className = rule[ 'rule' ].split( '/' )[ -1 ]
                if className.endswith( '.py' ):
                    className = className[ 0 : -3 ]
                newClass = getattr( loadModuleFrom( rule[ 'rule' ], 'hcp' ),
                                    className )
                newObj = newClass()
                cb = newObj.analyze
                rule = { 'name' : rule[ 'name' ], 
                         'original' : rule[ 'rule' ],
                         'rule' : cb,
                         'action' : eval( 'lambda event, sensor, report, page: ( %s )' % ( rule[ 'action' ], ), env, env ) }
            else:
                rule = { 'name' : rule[ 'name' ], 
                         'original' : rule[ 'rule' ],
                         'rule' : eval( 'lambda event, sensor: ( %s )' % ( rule[ 'rule' ], ), env, env ),
                         'action' : eval( 'lambda event, sensor, report, page: ( %s )' % ( rule[ 'action' ], ), env, env ) }
            return ( rule, None )
        except:
            exc = traceback.format_exc()
            self._actor.log( "Error compiling rule: %s" % exc )
            return ( None, exc )

    def saveRules( self ):
        resp = self.deploymentmanager.request( 'set_config', { 'conf' : 'global/quick_detects', 
                                                               'value' : json.dumps( self.conf ), 
                                                               'by' : 'quick_detect_host' } )
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

    def checkRule( self, rule, event, sensor ):
        try:
            if rule[ 'rule' ]( event, sensor ):
                def report( name = None, content = None, priority = 0 ):
                    if name is None:
                        return False

                    rep = { 'source' : sensor.aid, 
                            'msg_ids' : sensor.routing[ 'event_id' ], 
                            'cat' : name, 
                            'detect' : content or event._event, 
                            'detect_id' : uuid.uuid4(), 
                            'summary' : 'quick detect: %s' % rule[ 'original' ],
                            'priority' : priority }

                    resp = self.reporting.request( 'detect', rep )

                    if not resp.isSuccess:
                        self._actor.log( "Failed to report: %s" % str( resp ) )

                    return resp.isSuccess
                self._actor.zInc( 'detections.%s' % rule[ 'name' ] )
                self._actor.log( "!!! Rule %s matched." % ( rule[ 'name' ], ) )
                rule[ 'action' ]( event, sensor, report, self.page )
        except:
            self._actor.log( "Error evaluating %s: %s" % ( rule[ 'name' ], traceback.format_exc() ) )
            self._actor.zInc( 'error.%s' % rule[ 'name' ] )

    def getRules( self, msg ):
        return ( True, self.conf )

    def reloadRules( self, msg ):
        self._actor.log( "Fetching quick detects." )
        resp = self.deploymentmanager.request( 'get_quick_detects', {} )
        conf = {}
        rules = {}
        errors = []
        if resp.isSuccess:
            try:
                conf = json.loads( resp.data[ 'detects' ] )
                self._actor.log( "Found %d quick detects." % len( conf ) )
            except:
                errors.append( traceback.format_exc() )
                conf = {}
        else:
            self._actor.log( "No capabilities found." )

        for name, ruleInfo in conf.items():
            compiled, exc  = self.compileRule( ruleInfo )
            if compiled is None:
                errors.append( exc )
            else:
                rules[ name ] = compiled

        self.rules = rules
        self.conf = conf

        if 0 != len( errors ):
            return ( False, errors )

        self._actor.zSet( 'n_rules', len( self.conf ) )

        return ( True, )

    def analyze( self, routing, event, mtd ):
        if 0 == len( self.rules ):
            return True

        sensor = SensorContext( self, routing )
        tmpEvent = EventDSL( event, not sensor.aid.isWindows() )
        self._actor.parallelExec( lambda rule: self.checkRule( rule, tmpEvent, sensor ), self.rules.values() )

        self.stateful.shoot( 'analyze', ( routing, event, mtd ), key = routing[ 'aid' ] )

        self._actor.zInc( 'analyzed' )

        return True
