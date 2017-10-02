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
import traceback
import json
import uuid
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

    def isTagged( self, tag ):
        return tag.lower() in self.routing[ 'tags' ]

    def inOrg( self, oid ):
        return str( oid ) == str( self.aid.org_id )


class QuickDetectHost( Actor ):
    def init( self, parameters, resources ):
        self.rules = {}

        self.deploymentmanager = self.getActorHandle( resources[ 'deployment' ], nRetries = 3, timeout = 30 )
        self.models = self.getActorHandle( resources[ 'modeling' ], timeout = 30, nRetries = 3 )
        self.tagging = self.getActorHandle( resources[ 'tagging' ], timeout = 30, nRetries = 3 )
        self.reporting = self.getActorHandle( resources[ 'reporting' ], timeout = 30, nRetries = 3 )
        self.paging = self.getActorHandle( resources[ 'paging' ], timeout = 60, nRetries = 3 )
        self.tasking = self.getActorHandle( resources[ 'autotasking' ], 
                                             mode = 'affinity',
                                             timeout = 60,
                                             nRetries = 2 )

        self.conf = {}
        self.reloadRules( None )

        self.handle( 'add_rule', self.addRule )
        self.handle( 'del_rule', self.delRule )
        self.handle( 'get_rules', self.getRules )
        self.handle( 'reload_rules', self.reloadRules )
        self.handle( 'process', self.analyze )

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
            self.log( "Failed to page: %s" % str( resp ) )

        return resp.isSuccess

    def compileRule( self, rule ):
        env = {}
        env[ "locals" ]   = None
        env[ "globals" ]  = None
        env[ "__name__" ] = None
        env[ "__file__" ] = None
        env[ "__builtins__" ] = None

        try:
            rule = { 'name' : rule[ 'name' ], 
                     'original' : rule[ 'rule' ],
                     'rule' : eval( 'lambda event, sensor: ( %s )' % ( rule[ 'rule' ], ), env, env ),
                     'action' : eval( 'lambda event, sensor, report, page: ( %s )' % ( rule[ 'action' ], ), env, env ) }
            return ( rule, None )
        except:
            exc = traceback.format_exc()
            self.log( "Error compiling rule: %s" % exc )
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
        if name in self.rules:
            return ( False, 'rule already exists' )

        compiled, exc  = self.compileRule( req )
        if compiled is None:
            return ( False, exc )
        self.rules[ name ] = compiled
        self.conf[ name ] = { 'name' : name, 'rule' : rule, 'action' : action }

        return ( self.saveRules(), )

    def delRule( self, msg ):
        req = msg.data
        name = req[ 'name' ]
        if name not in self.rules:
            return ( False, 'rule not found' )
        self.rules.pop( name, None )
        self.conf.pop( name, None )
        self.log( "Removed rule %s." % name )
        return ( self.saveRules(), )

    def checkRule( self, rule, event, sensor ):
        try:
            if rule[ 'rule' ]( event, sensor ):
                def report( name = None, content = None ):
                    if name is None:
                        return False

                    rep = { 'source' : sensor.aid, 
                            'msg_ids' : sensor.routing[ 'event_id' ], 
                            'cat' : name, 
                            'detect' : event._event, 
                            'detect_id' : uuid.uuid4(), 
                            'summary' : 'quick detect: %s' % rule[ 'original' ],
                            'priority' : 0 }

                    resp = self.reporting.request( 'detect', rep )

                    if not resp.isSuccess:
                        self.log( "Failed to page: %s" % str( resp ) )

                    return resp.isSuccess
                self.zInc( 'detections.%s' % rule[ 'name' ] )
                self.log( "!!! Rule %s matched." % ( rule[ 'name' ], ) )
                rule[ 'action' ]( event, sensor, report, self.page )
        except:
            self.log( "Error evaluating %s: %s" % ( rule[ 'name' ], traceback.format_exc() ) )
            self.zInc( 'error.%s' % rule[ 'name' ] )

    def getRules( self, msg ):
        return ( True, self.conf )

    def reloadRules( self, msg ):
        self.log( "Fetching quick detects." )
        resp = self.deploymentmanager.request( 'get_quick_detects', {} )
        conf = {}
        rules = {}
        errors = []
        if resp.isSuccess:
            try:
                conf = json.loads( resp.data[ 'detects' ] )
                self.log( "Found %d quick detects." % len( conf ) )
            except:
                errors.append( traceback.format_exc() )
                conf = {}
        else:
            self.log( "No capabilities found." )

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

        self.zSet( 'n_rules', len( self.conf ) )

        return ( True, )

    def analyze( self, msg ):
        if 0 == len( self.rules ):
            return ( True, )

        routing, event, mtd = msg.data

        sensor = SensorContext( self, routing )
        tmpEvent = EventDSL( event, not sensor.aid.isWindows() )
        self.parallelExec( lambda rule: self.checkRule( rule, tmpEvent, sensor ), self.rules.values() )

        return ( True, )

if __name__ == "__main__":
    print( "Testing actor." )
    testActor = QuickDetectHost.initTestActor( resources = { 'modeling' : '', 
                                                             'tagging' : '', 
                                                             'detects' : '',
                                                             'report' : '',
                                                             'autotasking' : '' } )
    testEvent1 = testActor.mockRequest( ( { 'aid' : '0.0.0.10000000.0' }, 
                                          { "notification.NETWORK_SUMMARY": {
                                                "hbs.PARENT_ATOM": "d4ccf684-916c-119f-d642-96d5c40a4dcf", 
                                                "hbs.THIS_ATOM": "034dbdd5-71f2-c0c2-6692-b29f9f905de4", 
                                                "base.TIMESTAMP": 1506143083618, 
                                                "base.PROCESS": {
                                                  "base.PARENT": {
                                                    "base.PARENT_PROCESS_ID": 0, 
                                                    "base.COMMAND_LINE": "/sbin/launchd", 
                                                    "base.PROCESS_ID": 1, 
                                                    "base.FILE_PATH": "/sbin/launchd", 
                                                    "base.USER_NAME": "root", 
                                                    "base.USER_ID": 0
                                                  }, 
                                                  "base.PARENT_PROCESS_ID": 1, 
                                                  "base.COMMAND_LINE": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", 
                                                  "base.PROCESS_ID": 354, 
                                                  "hbs.PARENT_ATOM": "1d711cea-3258-eaa4-51af-0103be3336f5", 
                                                  "base.FILE_PATH": "/Applications/Google Chrome.app/Contents/Versions/60.0.3112.113/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper", 
                                                  "base.NETWORK_ACTIVITY": [
                                                    {
                                                      "base.PROCESS_ID": 354, 
                                                      "hbs.PARENT_ATOM": "d4ccf684-916c-119f-d642-96d5c40a4dcf", 
                                                      "base.DESTINATION": {
                                                        "base.IP_ADDRESS": "239.255.255.250", 
                                                        "base.PORT": 1900
                                                      }, 
                                                      "base.IS_OUTGOING": 1, 
                                                      "hbs.THIS_ATOM": "38b34d6d-43e1-e978-5c29-5f68cb5b6450", 
                                                      "base.TIMESTAMP": 1506143068324, 
                                                      "base.SOURCE": {
                                                        "base.IP_ADDRESS": "192.168.1.218", 
                                                        "base.PORT": 52345
                                                      }
                                                    }, 
                                                    {
                                                      "base.PROCESS_ID": 354, 
                                                      "hbs.PARENT_ATOM": "d4ccf684-916c-119f-d642-96d5c40a4dcf", 
                                                      "base.DESTINATION": {
                                                        "base.IP_ADDRESS": "239.255.255.250", 
                                                        "base.PORT": 1900
                                                      }, 
                                                      "base.IS_OUTGOING": 1, 
                                                      "hbs.THIS_ATOM": "3a01ef5f-2039-4ee0-f1d7-651985ecb98e", 
                                                      "base.TIMESTAMP": 1506143068324, 
                                                      "base.SOURCE": {
                                                        "base.IP_ADDRESS": "192.168.6.1", 
                                                        "base.PORT": 61493
                                                      }
                                                    }
                                                  ], 
                                                  "base.USER_NAME": "maxime", 
                                                  "base.USER_ID": 501, 
                                                  "hbs.THIS_ATOM": "d4ccf684-916c-119f-d642-96d5c40a4dcf", 
                                                  "base.TIMESTAMP": 1506143068328
                                                }
                                              }
                                            }, 
                                          {} ) )
    testEvent2 = testActor.mockRequest( ( { 'aid' : '0.0.0.10000000.0' }, 
                                          {
                                            "notification.DNS_REQUEST": {
                                                "base.PROCESS_ID": 354,
                                                "base.DOMAIN_NAME": "plus.l.google.com",
                                                "hbs.PARENT_ATOM": "351862a3-73a7-a2c0-8f61-408f645a9c8e",
                                                "base.IP_ADDRESS": "216.58.194.206",
                                                "base.MESSAGE_ID": 2112,
                                                "base.DNS_TYPE": 1,
                                                "base.TIMESTAMP": 1506143008784,
                                                "hbs.THIS_ATOM": "c5619e9c-5fa6-ed66-6c84-c88be898b785"
                                            }
                                          }, 
                                          {} ) )
    res = testActor.addRule( testActor.mockRequest( { 'name' : 'test1', 
                                                      'rule' : r'event.NetworkSummary()',
                                                      'action' : None } ) )
    assert( res[ 0 ] )
    
    res = testActor.analyze( testEvent2 )
    assert( None == testActor.zGet( 'detections.test1' ) )
    
    res = testActor.analyze( testEvent1 )
    assert( 1 == testActor.zGet( 'detections.test1' ) )

    res = testActor.delRule( testActor.mockRequest( { 'name' : 'test1' } ) )
    assert( res[ 0 ] )

    res = testActor.addRule( testActor.mockRequest( { 'name' : 'test2', 
                                                      'rule' : r'event.Dns( domainEndsWith = ".3322.org" )',
                                                      'action' : None } ) )
    assert( res[ 0 ] )

    res = testActor.analyze( testEvent2 )
    assert( None == testActor.zGet( 'detections.test2' ) )

    res = testActor.addRule( testActor.mockRequest( { 'name' : 'test3', 
                                                      'rule' : r'event.Dns( domainEndsWith = ".google.com" )',
                                                      'action' : r'sensor.tag( "test_tag" )' } ) )
    assert( res[ 0 ] )

    res = testActor.analyze( testEvent2 )
    assert( 1 == testActor.zGet( 'detections.test1' ) )
    assert( None == testActor.zGet( 'detections.test2' ) )
    assert( 1 == testActor.zGet( 'detections.test3' ) )

    res = testActor.addRule( testActor.mockRequest( { 'name' : 'test4', 
                                                      'rule' : '''event.Process( pathEndsWith = "Google Chrome Helper" )
                                                                  and
                                                                  event.Connections( srcIpIn = "192.168.6.1/32", dstPort = 1900 )''',
                                                      'action' : r'sensor.task( [ "file_dir", "." ] )' } ) )
    assert( res[ 0 ] )

    res = testActor.analyze( testEvent1 )
    assert( 1 == testActor.zGet( 'detections.test4' ) )