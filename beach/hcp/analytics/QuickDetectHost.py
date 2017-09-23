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
EventDSL = Actor.importLib( '../utils/EventInterpreter', 'EventDSL' )
AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )

class QuickDetectHost( Actor ):
    def init( self, parameters, resources ):
        self.log( "starting" )
        self.rules = {}

        self.handle( 'add_rule', self.addRule )
        self.handle( 'del_rule', self.delRule )
        self.handle( 'analyze', self.analyze )

    def deinit( self ):
        pass

    def addRule( self, msg ):
        req = msg.data
        name = req[ 'name' ]
        rule = req[ 'rule' ]
        action = req.get( 'action', None )
        if name in self.rules:
            return ( False, 'rule already exists' )
        self.rules[ name ] = { 'name' : name, 
                               'rule' : eval( 'lambda event, routing: ( %s )' % ( rule, ), {}, {} ),
                               'action' : action }
        self.log( "Added rule %s." % name )
        return ( True, )

    def delRule( self, msg ):
        req = msg.data
        name = req[ 'name' ]
        if name not in self.rules:
            return ( False, 'rule not found' )
        self.rules.pop( name, None )
        self.log( "Removed rule %s." % name )
        return ( True, )

    def analyze( self, msg ):
        routing, event, mtd = msg.data

        tmpEvent = EventDSL( event, not AgentId( routing[ 'aid' ] ).isWindows() )
        for rule in self.rules.values():
            if rule[ 'rule' ]( tmpEvent, routing ):
                self.zInc( 'detections.%s' % rule[ 'name' ] )
                self.log( "!!! Rule %s matched." % ( rule[ 'name' ], ) )
                if rule[ 'action' ] is not None:
                    pass

        return ( True, )


if __name__ == "__main__":
    print( "Testing actor." )
    testActor = QuickDetectHost.initTestActor()
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
                                                      'action' : None } ) )
    assert( res[ 0 ] )

    res = testActor.analyze( testEvent2 )
    assert( 1 == testActor.zGet( 'detections.test1' ) )
    assert( None == testActor.zGet( 'detections.test2' ) )
    assert( 1 == testActor.zGet( 'detections.test3' ) )

    res = testActor.addRule( testActor.mockRequest( { 'name' : 'test4', 
                                                      'rule' : '''event.Process( pathEndsWith = "Google Chrome Helper" )
                                                                  and
                                                                  event.Connections( srcIpIn = "192.168.6.1/32", dstPort = 1900 )''',
                                                      'action' : None } ) )
    assert( res[ 0 ] )

    res = testActor.analyze( testEvent1 )
    assert( 1 == testActor.zGet( 'detections.test4' ) )