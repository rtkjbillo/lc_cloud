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
from slacker import Slacker
from slackclient import SlackClient
import json
import uuid
import base64
from sets import Set
import datetime
import shlex
import traceback
import copy
import time
import re
import dateutil.parser
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )
_x_ = Actor.importLib( 'utils/hcp_helpers', '_x_' )
InvestigationNature = Actor.importLib( 'utils/hcp_helpers', 'InvestigationNature' )
InvestigationConclusion = Actor.importLib( 'utils/hcp_helpers', 'InvestigationConclusion' )
ObjectTypes = Actor.importLib( 'utils/ObjectsDb', 'ObjectTypes' )
Event = Actor.importLib( 'utils/hcp_helpers', 'Event' )
EventInterpreter = Actor.importLib( 'utils/EventInterpreter', 'EventInterpreter' )

class _TaskResp ( object ):
    def __init__( self, trxId, actor ):
        self._trxId = trxId
        self._actor = actor
        self.wasReceived = False
        self.responses = []
        self._event = Event()
    
    def _add( self, newData ):
        if 'hbs.CLOUD_NOTIFICATION' == newData.keys()[ 0 ]:
            self.wasReceived = True
        else:
            self.responses.append( newData )
            self._event.set()
    
    def wait( self, timeout ):
        return self._event.wait( timeout )

    def done( self ):
        self._actor.unhandle( self._trxId )

class SlackRep( Actor ):
    def init( self, parameters, resources ):
        self.channel_allDetects = parameters.get( 'channel_all_detects', 'all_detects' )

        self.audit = self.getActorHandle( resources[ 'auditing' ], timeout = 30, nRetries = 3 )
        self.model = self.getActorHandle( resources[ 'modeling' ], timeout = 120, nRetries = 2 )
        self.deployment = self.getActorHandle( resources[ 'deployment' ], timeout = 30, nRetries = 3 )
        self.identManager = self.getActorHandle( resources[ 'identmanager' ], timeout = 30, nRetries = 3 )
        self.sensordir = self.getActorHandle( resources[ 'sensordir' ], timeout = 30, nRetries = 3 )
        self.tasking = self.getActorHandle( resources[ 'autotasking' ], timeout = 30, nRetries = 3 )
        self.huntmanager = self.getActorHandle( resources[ 'huntsmanager' ], timeout = 30, nRetries = 3 )
        self.reporting = self.getActorHandle( resources[ 'reporting' ], timeout = 30, nRetries = 3 )

        self.reps = {}
        self.uiDomain = 'http://limacharlie:8888'

        self.schedule( 60, self.refreshBots )

        self.handle( 'report_inv', self.reportInv )
        self.handle( 'report_detect', self.reportDetect )
        
    def deinit( self ):
        pass

    def refreshBots( self ):
        globalConfigs = self.deployment.request( 'get_global_config', {} )
        if globalConfigs.isSuccess:
            self.uiDomain = globalConfigs.data[ 'global/uidomain' ]
        allOrgs = self.identManager.request( 'get_org_info', { 'include_all' : True } )
        if allOrgs.isSuccess:
            for oName, oid, _ in allOrgs.data[ 'orgs' ]:
                oid = uuid.UUID( oid )
                oConf = self.deployment.request( 'get_org_config', { 'oid' : oid } )
                if oConf.isSuccess:
                    oToken = oConf.data[ '%s/slack_token' % oid ]
                    botToken = oConf.data[ '%s/slack_bot_token' % oid ]
                    if '' != oToken and oid not in self.reps:
                        self.log( "Loading new slack app for %s" % oid )
                        self.reps[ oid ] = RepInstance( self, oid, oToken, botToken )

    def getSources( self, event ):
        return [ AgentId( x ) for x in event[ 'source' ].split( ' / ' ) ]

    def reportInv( self, msg ):
        self.log( "Received investigation" )
        detect = msg.data
        sources = self.getSources( detect )
        oids = Set( [ x.org_id for x in sources ] )
        for oid in oids:
            rep = self.reps.get( oid, None )
            if rep is not None:
                rep.newInvestigation( sources, detect )
        return ( True, )

    def reportDetect( self, msg ):
        self.log( "Received detection" )
        detect = msg.data
        sources = self.getSources( detect )
        oids = Set( [ x.org_id for x in sources ] )
        for oid in oids:
            rep = self.reps.get( oid, None )
            if rep is not None:
                rep.newDetect( sources, detect )
        return ( True, )

class CommandContext( object ):
    def __init__( self, channel, user, cmd, history ):
        self.channel = channel
        self.user = user
        self.cmd = cmd
        self.history = history


class RepInstance( object ):
    def __init__( self, actor, oid, apiToken, botToken ):
        self.actor = actor
        self.oid = oid
        self.apiToken = apiToken
        self.botToken = botToken
        self.slack = Slacker( self.apiToken )
        self.bot = SlackClient( self.botToken )
        self.botId = None
        self.invId = str( uuid.uuid4() )
        self.taskId = 0
        self.slackLinkRE = re.compile( r'<.+://.+\|(.+)>' )
        resp = self.actor.huntmanager.request( 'reg_inv', { 'uid' : self.actor.name, 'name' : self.invId } )
        if not resp.isSuccess:
            raise Exception( 'failed to register investigation id for tasking: %s' % resp )

        self.history = { 'last_cmd' : [] }

        self.makeChannel( '#detects' )

        if not self.bot.rtm_connect():
            raise Exception( 'failed to connect bot to Slack rtm API' )

        self.actor.newThread( self.botThread )

    def botThread( self, stopEvent ):
        try:
            # Get our ID
            api_call = self.bot.api_call( "users.list" )
            if api_call.get( 'ok' ):
                for user in api_call.get( 'members' ):
                    if user.get( 'name', '' ) == self.bot.server.username:
                        self.botId = user.get( 'id' )
                        break

            self.actor.log( "found our id %s for %s" % ( self.botId, self.bot.server.username ) )
            #self.bot.rtm_send_message( '#general', 'Reporting in.' )

            while not stopEvent.wait( 1.0 ):
                for slackMessage in self.tryToRead():
                    message = unicode( slackMessage.get( 'text' ) )
                    fromUser = slackMessage.get( 'user' )
                    channel = slackMessage.get( 'channel' )
                    if not message or not fromUser or ( '<@%s>' % self.botId ) not in message:
                        continue
                    # Fixing silly quotes form unicode to ascii
                    message = message.replace( u'\u201c', '"' )
                    message = message.replace( u'\u201d', '"' )
                    try:
                        ctx = CommandContext( channel, 
                                              fromUser, 
                                              [ self.stripSlackFormatting( x ) for x in shlex.split( message.replace( '<@%s>' % self.botId, '' ) ) ], 
                                              copy.deepcopy( self.history ) )
                    except:
                        self.bot.rtm_send_message( channel, "error parsing command `%s`: %s" % ( message, traceback.format_exc(), ) )
                    self.actor.newThread( self.executeCommand, ctx )

        except:
            self.actor.log( "Excp: %s while parsing %s" % ( traceback.format_exc(), message ) )
            self.bot.rtm_send_message( "#general", "oops I've fallen and I can't get up: %s" % ( traceback.format_exc(), ) )
            del( self.actor.reps[ oid ] )

        self.actor.log( "bot terminating" )

    def tryToRead( self ):
        while True:
            try:
                return self.bot.rtm_read()
            except:
                self.bot = SlackClient( self.botToken )
                self.bot.rtm_connect()

    def executeCommand( self, stopEvent, ctx ):
        try:
            if 'help' == ctx.cmd[ 0 ]:
                self.sendHelp( ctx )
            elif '?' == ctx.cmd[ 0 ] and 2 <= len( ctx.cmd ):
                self.command_objects( ctx )
            elif '*' == ctx.cmd[ 0 ]:
                self.command_status( ctx )
            elif '.' == ctx.cmd[ 0 ] and 2 == len( ctx.cmd ):
                self.command_host_info( ctx )
            elif '!' == ctx.cmd[ 0 ] and 2 < len( ctx.cmd ):
                self.command_task( ctx )
            elif 'close' == ctx.cmd[ 0 ] and ( 1 == len( ctx.cmd ) or 2 == len( ctx.cmd ) ):
                self.command_close( ctx )
            elif '&gt;' == ctx.cmd[ 0 ] and 2 == len( ctx.cmd ):
                self.command_parent_atom( ctx )
            elif '&lt;' == ctx.cmd[ 0 ] and 2 == len( ctx.cmd ):
                self.command_children_atom( ctx )
            elif '~' == ctx.cmd[ 0 ] and ( 2 == len( ctx.cmd ) or  4 <= len( ctx.cmd ) ):
                self.command_traffic( ctx )
            else:
                self.bot.rtm_send_message( ctx.channel, "what are you talking about, need *help*?" )
        except:
            self.bot.rtm_send_message( ctx.channel, "oops I've fallen and I can't get up: %s" % ( traceback.format_exc(), ) )
            self.actor.log( "Excp: %s" % traceback.format_exc() )

        self.history[ 'last_cmd' ] = ctx.cmd

    def isSensorAllowed( self, ctx, sid ):
        aid = AgentId( sid )
        if aid.org_id is None:
            resp = self.actor.model.request( 'get_sensor_info', { 'id_or_host' : aid } )
            if resp.isSuccess:
                aid = AgentId( resp.data[ 'id' ] )
        if aid.org_id == self.oid:
            return True
        self.bot.rtm_send_message( ctx.channel, "sensor not allowed" )
        return False

    def sendHelp( self, ctx ):
        self.bot.rtm_send_message( ctx.channel, self.prettyJson( 
        {
            'help' : 'this help',
            '?' : [ '? <object_name>: lists the objects of any types with that name',
                    '? <object_name> <object_type> . [of_type]: lists the locations where the object was seen',
                    '? <object_name> <object_type> > [of_type]: lists all the parents of the object',
                    '? <object_name> <object_type> < [of_type}: lists all the children of the object' ],
            '!' : [ '! sensor_id command [arguments...]: execute the command on the sensor, investigation sensor if sensor id not specified' ],
            '>' : [ '> atom_id: get the parent event chain starting at this atom_id.' ],
            '<' : [ '< atom_id: get all the direct children of this atom_id.' ],
            '.' : [ '. [hostname | sensor_id]: get information on a host by name or sensor id' ],
            'close' : [ 'close inv_id: closes the specific inv_id with that conclusion.',
                        'close: closes the inv_id from the current channel with that conclusion.' ],
            '~' : [ '~ atom_id: display the event content with that atom_id.',
                    '~ sensor_id from_time to_time [of_type ...]: display event summaries for all events on sensor_id from from_time to to_time, optionally only of types of_type.' ]
        } ) )

    def command_close( self, ctx ):
        if 1 == len( ctx.cmd ):
            #TODO conclude the investigation, tricky a bit because we need the Hunter.
            self.actor.log( "Archiving channel %s" % ctx.channel )
            self.archiveChannel( ctx.channel )
        elif 2 == len( ctx.cmd ):
            #TODO conclude the investigation, tricky a bit because we need the Hunter.
            self.actor.log( "Archiving channel %s" % ctx.cmd[ 1 ] )
            self.archiveChannel( ctx.cmd[ 1 ] )

    def command_objects( self, ctx ):
        if 2 == len( ctx.cmd ):
            # Query for object types that match the name
            data = self.getModelData( 'get_obj_list', { 'orgs' : self.oid, 'name' : ctx.cmd[ 1 ] } )
            if data is not None:
                self.bot.rtm_send_message( ctx.channel, "here are the objects matching:\n%s\n(valid object types: %s)" % 
                                                        ( self.prettyJson( [ x for x in data[ 'objects' ] if 'RELATION' != x[ 2 ] ] ), str( ObjectTypes.forward.keys() ) ) )
        elif 4 <= len( ctx.cmd ):
            # Query for a characteristic of the object
            if '.' == ctx.cmd[ 3 ]:
                # Query the locations of the object
                data = self.getModelData( 'get_obj_view', { 'orgs' : self.oid, 
                                                            'obj_name' : ctx.cmd[ 1 ], 
                                                            'obj_type' : ctx.cmd[ 2 ].upper() } )
                aid = AgentId( '%s.0.0.0.0' % self.oid )
                if data is not None:
                    output = []
                    output.append( '*Globally*: %s hosts' % data[ 'locs' ].get( data[ 'id' ], '-' ) )
                    for loc in data[ 'olocs' ]:
                        output.append( "*%s*" % ( self.getHostname( loc[ 0 ] ) ) )
                        output.append( '  Last Seen: %s' % self.msTsToTime( loc[ 1 ] ) )
                        output.append( '  SID: %s)\n' % loc[ 0 ] )
                    self.bot.rtm_send_message( ctx.channel, "locations of object *%s* (%s):\n%s" % ( ctx.cmd[ 1 ],
                                                                                                     ctx.cmd[ 2 ].upper(),
                                                                                                     "\n".join( output ) ) )
            elif '&gt;' == ctx.cmd[ 3 ]:
                # Query the parents of the object
                typeFilter = None
                if 5 == len( ctx.cmd ):
                    typeFilter = ctx.cmd[ 4 ].upper()
                data = self.getModelData( 'get_obj_view', { 'orgs' : self.oid, 
                                                            'obj_name' : ctx.cmd[ 1 ], 
                                                            'obj_type' : ctx.cmd[ 2 ].upper() } )
                if data is not None:
                    output = []
                    for parent in data[ 'parents' ]:
                        if typeFilter is not None and typeFilter != parent[ 2 ]: 
                            continue
                        output.append( '*%s* (%s)' % ( parent[ 1 ], parent[ 2 ] ) )
                        output.append( '  Hosts w/ object: %s' % data[ 'locs' ].get( parent[ 0 ], '-' ) )
                        output.append( '  Hosts w/ relation: %s\n' % data[ 'rlocs' ].get( parent[ 0 ], '-' ) )
                    self.bot.rtm_send_message( ctx.channel, "parents of object *%s* (%s):\n%s" % ( ctx.cmd[ 1 ],
                                                                                                   ctx.cmd[ 2 ].upper(),
                                                                                                   "\n".join( output ) ) )
            elif '&lt;' == ctx.cmd[ 3 ]:
                # Query the children of the object
                if 5 == len( ctx.cmd ):
                    typeFilter = ctx.cmd[ 4 ].upper()
                data = self.getModelData( 'get_obj_view', { 'orgs' : self.oid, 
                                                            'obj_name' : ctx.cmd[ 1 ], 
                                                            'obj_type' : ctx.cmd[ 2 ].upper() } )
                if data is not None:
                    output = []
                    for child in data[ 'children' ]:
                        if typeFilter is not None and typeFilter != child[ 2 ]: 
                            continue
                        output.append( '*%s* (%s)' % ( child[ 1 ], child[ 2 ] ) )
                        output.append( '  Hosts w/ object: %s' % data[ 'locs' ].get( child[ 0 ], '-' ) )
                        output.append( '  Hosts w/ relation: %s\n' % data[ 'rlocs' ].get( child[ 0 ], '-' ) )
                    self.bot.rtm_send_message( ctx.channel, "children of object *%s* (%s):\n%s" % ( ctx.cmd[ 1 ],
                                                                                                    ctx.cmd[ 2 ].upper(),
                                                                                                    "\n".join( output ) ) )
        else:
            self.sendHelp( ctx )

    def command_status( self, ctx ):
        orgSensors = self.getOrgSensors()
        sensorDir = self.getSensorDir()
        winSensors = 0
        osxSensors = 0
        linSensors = 0
        winOnline = 0
        osxOnline = 0
        linOnline = 0
        onlineSensors = []
        for sid, sensorInfo in orgSensors.iteritems():
            aid = AgentId( sensorInfo[ 'aid' ] )
            isOnline = False
            if sid in sensorDir:
                isOnline = True
                _, _, curBytes, connectedAt = sensorDir[ sid ]
                onlineSensors.append( ( curBytes, connectedAt, sid ) )
            if aid.isWindows():
                winSensors += 1
                if isOnline:
                    winOnline += 1
            if aid.isMacOSX():
                osxSensors += 1
                if isOnline:
                    osxOnline += 1
            if aid.isLinux():
                linSensors += 1
                if isOnline:
                    linOnline += 1

        del( sensorDir )

        output = []
        output.append( 'Sensor Status:' )
        output.append( '  *Windows:* %d (%d online)' % ( winSensors, winOnline ) )
        output.append( '  *MacOS:* %d (%d online)' % ( osxSensors, osxOnline ) )
        output.append( '  *Linux:* %d (%d online)' % ( linSensors, linOnline ) )
        output.append( '' )

        topTraffic = sorted( onlineSensors, key = lambda x: x[ 0 ], reverse = True )[ : 5 ]
        output.append( 'Top online sensors by data received:' )
        output.append( self.prettyJson( [ { "hostname" : self.getHostname( x[ 2 ] ), 
                                            "sid" : x[ 2 ],
                                            "since" : self.sTsToTime( x[ 1 ] ),
                                            "bytes" : x[ 0 ] } for x in topTraffic ] ) )
        
        self.bot.rtm_send_message( ctx.channel, "\n".join( output ) )

    def command_task( self, ctx ):
        dest = self.getHostInfo( ctx.cmd[ 1 ] )[ 'id' ]
        if not self.isSensorAllowed( ctx, dest ): return
        for token in ctx.cmd:
            if token in ( '-!', '-x', '-@' ):
                self.bot.rtm_send_message( ctx.channel, "special CLI flags -x, -! and -@ are not allowed." )
                return
        taskFuture = self.task( ctx, dest, ctx.cmd[ 2 : ] )
        if taskFuture is not None:
            try:
                if taskFuture.wait( 120 ):
                    start = time.time()
                    while time.time() < start + 30:
                        try:
                            resp = taskFuture.responses.pop()
                            data = self.prettyJson( resp )
                            atom = base64.b64decode( _x_( resp, '?/hbs.THIS_ATOM' ) )
                            self.slack.chat.post_message( ctx.channel, 
                                                          attachments = [ { "text" : data, 
                                                                            "pretext" : "Result from *%s* on *%s*" % ( str( ctx.cmd[ 2 : ] ), AgentId( dest ).sensor_id ),
                                                                            "fallback" : "received task response",
                                                                            "mrkdwn_in" : [ "text", "pretext" ],
                                                                            "fields" : [ { "link" : "%s/explore?atid=%s" % ( self.actor.uiDomain, uuid.UUID( bytes = atom ) ) } ] } ] )
                        except IndexError:
                            time.sleep( 1 )
                elif taskFuture.wasReceived:
                    self.actor.log( taskFuture.responses )
                    self.slack.chat.post_message( ctx.channel, "... task was received but no reply received" )
                else:
                    self.slack.chat.post_message( ctx.channel, "... haven't received a reply" )
            finally:
                taskFuture.done()

    def command_parent_atom( self, ctx ):
        interpreter = EventInterpreter()
        data = []
        for evt in self.crawlUpParentTree( None, rootAtom = ctx.cmd[ 1 ] ):
            interpreter.setEvent( evt )
            data.append( { "type" : interpreter.name(),
                           "atom" : interpreter.getAtom(),
                           "narrative" : interpreter.narrative() } )
            
        render = self.sanitizeJson( { "fallback" : "Events going up from: %s." % ctx.cmd[ 1 ],
                                      "pretext" : "Events going up from: %s." % ctx.cmd[ 1 ],
                                      "text" : self.prettyJson( data ),
                                      "mrkdwn_in" : [ "text", "pretext" ] } )
        self.slack.chat.post_message( ctx.channel, attachments = [ render ] )
        

    def command_children_atom( self, ctx ):
        interpreter = EventInterpreter()
        children = self.getChildrenAtoms( ctx.cmd[ 1 ], depth = 1 )
        if children is None:
            self.slack.chat.post_message( ctx.channel, "couldn't fetch children for %s" % ctx.cmd[ 1 ] )
        else:
            data = []
            for evt in children:
                interpreter.setEvent( evt )
                data.append( { "type" : interpreter.name(),
                               "atom" : interpreter.getAtom(),
                               "narrative" : interpreter.narrative() } )
            render = self.sanitizeJson( { "fallback" : "Direct children events of: %s." % ctx.cmd[ 1 ],
                                          "pretext" : "Direct children events of: %s." % ctx.cmd[ 1 ],
                                          "text" : self.prettyJson( data ),
                                          "mrkdwn_in" : [ "text", "pretext" ] } )
            self.slack.chat.post_message( ctx.channel, attachments = [ render ] )

    def command_host_info( self, ctx ):
        hostOrId = ctx.cmd[ 1 ]
        hostInfo = self.getHostInfo( hostOrId )
        if not self.isSensorAllowed( ctx, hostInfo[ 'id' ] ): return
        self.bot.rtm_send_message( ctx.channel, "host info for *%s*: %s" % ( ctx.cmd[ 1 ], self.prettyJson( hostInfo ) ) )

    def command_traffic( self, ctx ):
        if 2 == len( ctx.cmd ):
            self.slack.chat.post_message( ctx.channel, 
                                          attachments = [ { "fallback" : "event",
                                                            "mrkdwn_in" : [ "text", "pretext" ],
                                                            "pretext" : "Event %s" % ctx.cmd[ 1 ],
                                                            "text" : self.prettyJson( self.getSingleAtom( ctx.cmd[ 1 ] ) ) } ] )
        elif 4 <= len( ctx.cmd ):
            self.actor.log( "CMD: %s" % str(ctx.cmd) )
            _, aid, after, before = ctx.cmd[ : 4 ]
            try:
                aid = AgentId( aid )
            except:
                aid = AgentId( self.getHostInfo( aid )[ 'id' ] )
            ofTypes = ctx.cmd[ 4 : ]
            if 0 == len( ofTypes ):
                ofTypes = None
            else:
                ofTypes = [ x if '.' in x else ( 'notification.%s' % x.upper() ) for x in ofTypes ]
            try:
                after = int( after )
            except:
                after = ( dateutil.parser.parse( after ) - datetime.datetime( 1970, 1, 1 ) ).total_seconds()
            try:
                before = int( before )
            except:
                before = ( dateutil.parser.parse( before ) - datetime.datetime( 1970, 1, 1 ) ).total_seconds()
            if not self.isSensorAllowed( ctx, aid ): return
            interpreter = EventInterpreter()
            timeline = self.getModelData( 'get_timeline', { 'id' : aid, 
                                                            'after' : after, 
                                                            'before' : before,
                                                            'types' : ofTypes,
                                                            'is_include_content' : True } )
            if timeline is None: return
            events = []
            for data in timeline[ 'events' ]:
                interpreter.setEvent( data[ 3 ] )
                events.append( { "type" : interpreter.name(),
                                 "atom" : interpreter.getAtom(),
                                 "narrative" : interpreter.narrative() } )
            render = self.sanitizeJson( { "fallback" : "Traffic for %s between %s and %s." % ( aid.sensor_id, after, before ),
                                          "pretext" : "Traffic for %s between %s and %s." % ( aid.sensor_id, after, before ),
                                          "text" : self.prettyJson( events ),
                                          "mrkdwn_in" : [ "text", "pretext" ] } )
            self.slack.chat.post_message( ctx.channel, attachments = [ render ] )

    def getModelData( self, request, requestData = {} ):
        resp = self.actor.model.request( request, requestData, timeout = 10.0 )
        if resp.isSuccess:
            return resp.data
        else:
            self.actor.log( "error getting data from model: %s" % str( resp ) )
            return None

    def getSensorDir( self ):
        directory = {}
        data = self.actor.sensordir.request( 'get_dir', {} )
        if data.isSuccess:
            directory = data.data[ 'dir' ]
        return directory

    def getOrgSensors( self ):
        sensors = {}
        aid = AgentId( '%s.0.0.0.0' % self.oid )
        data = self.getModelData( 'list_sensors', { 'aid' : aid } )
        if data is not None:
            sensors = data
        return sensors

    def sanitizeJson( self, o ):
        if type( o ) is dict:
            for k, v in o.iteritems():
                o[ k ] = self.sanitizeJson( v )
        elif type( o ) is list or type( o ) is tuple:
            o = [ self.sanitizeJson( x ) for x in o ]
        elif type( o ) in ( uuid.UUID, AgentId ):
            o = str( o )
        else:
            try:
                if ( type(o) is str or type(o) is unicode ) and "\x00" in o: raise Exception()
                json.dumps( o )
            except:
                o = base64.b64encode( o )

        return o

    def prettyJson( self, o, indent = 2 ):
        txt = json.dumps( self.sanitizeJson( o ), indent = indent )
        overflow = ''
        if 7000 < len( txt ):
            txt = txt[ : 7000 ]
            overflow = '\n\n*output too large...*'
        return '```%s```%s' % ( txt, overflow )

    def stripSlackFormatting( self, token ):
        res = self.slackLinkRE.match( token )
        if res is not None:
            return res.groups()[ 0 ]
        return token

    def makeChannel( self, name ):
        try:
            self.slack.channels.create( '%s' % name )
        except:
            return False
        return True

    def archiveChannel( self, name ):
        try:
            # Remove the prefix #
            name1 = name.lower()
            name2 = name[ 1 : ].lower()
            cid = None
            for channel in self.slack.channels.list().body[ 'channels' ]:
                if channel[ 'name' ].lower() in ( name1, name2 ) or channel[ 'id' ].lower() in ( name1, name2 ):
                    cid = channel[ 'id' ]
                    break
            if cid is not None:
                self.slack.channels.archive( cid )
        except:
            self.bot.rtm_send_message( name, "error archiving channel (%s): %s" % ( cid, traceback.format_exc(), ) )
            self.actor.log( "Excp: %s" % traceback.format_exc() )
            return False
        return True

    def inviteToChannel( self, name ):
        try:
            name1 = name.lower()
            name2 = name[ 1 : ].lower()
            cid = None
            for channel in self.slack.channels.list().body[ 'channels' ]:
                if channel[ 'name' ].lower() in ( name1, name2 ) or channel[ 'id' ].lower() in ( name1, name2 ):
                    cid = channel[ 'id' ]
                    break
            if cid is not None:
                self.slack.channels.invite( cid, self.botId )
            else:
                self.actor.log( "Channel not found: %s" % name )
        except:
            self.actor.log( 'EXC: %s' % traceback.format_exc() )
            return False
        return True

    def getHostname( self, aid ):
        try:
            return self.actor.model.request( 'get_sensor_info', { 'id_or_host' : str( aid ) } ).data[ 'hostname' ]
        except:
            return '-'

    def getHostInfo( self, aidOrHostnam ):
        try:
            return self.actor.model.request( 'get_sensor_info', { 'id_or_host' : str( aidOrHostnam ) } ).data
        except:
            return None

    def msTsToTime( self, ts ):
        if type( ts ) in ( str, unicode ):
            ts = ts.split( '.' )[ 0 ]
        return datetime.datetime.fromtimestamp( float( ts ) / 1000 ).strftime( '%Y-%m-%d %H:%M:%S.%f' )

    def sTsToTime( self, ts ):
        return self.msTsToTime( ts * 1000 ).split( '.' )[ 0 ]

    def newDetect( self, sources, detect ):
        hostNames = [ self.getHostname( x ) for x in sources ]
        atom = _x_( detect[ 'detect' ], '?/hbs.THIS_ATOM' )
        message = [ 'Detected *%s* on *%s*:' % ( detect[ 'cat' ], ', '.join( hostNames ) ) ]
        message.append( 'Summary: %s.' % detect[ 'summary' ] )
        message.append( 'Link to sensor: %s' % ' '.join( [ ( '%s/sensor?sid=%s' % ( self.actor.uiDomain, x.sensor_id ) ) for x in sources ] ) )
        if atom is not None:
            message.append( 'Link to event: %s/explore?atid=%s' % ( self.actor.uiDomain, uuid.UUID( bytes = atom ) ) )
        detectAttachment = { "text" : self.prettyJson( detect[ 'detect' ] ), 
                             "fallback" : "Detection Data",
                             "mrkdwn_in": [ "text", "pretext" ] }
        self.slack.chat.post_message( '#detects', '\n'.join( message ), attachments = [ detectAttachment ] )

    def renderInvHeader( self, inv, sources ):
        render = { "fallback" : "New investigation (ID: %s) created on %s." % ( inv[ 'inv_id' ], inv[ 'generated' ] ),
                   "pretext" : "New investigation.",
                   "author_name" : inv[ 'hunter' ],
                   "fields" : [],
                   "mrkdwn_in": [ "text", "pretext" ] }
        for source in sources:
            render[ "fields" ].append( { "title" : self.getHostname( source ), "value" : source.sensor_id, "short" : True } )
        return self.sanitizeJson( render )

    def renderNewTasking( self, inv, task ):
        render = { "fallback" : "New tasking sent: %s." % str( task[ 'data' ] ),
                   "pretext" : "New tasking sent: `%s`." % task[ 'why' ],
                   "text" : self.prettyJson( task[ 'data' ], indent = None ),
                   "fields" : [ { "title" : "Sent", "value" : ( "yes" if task[ 'sent' ] else "no" ), "short" : True } ],
                   "mrkdwn_in": [ "text", "pretext" ] }
        return self.sanitizeJson( render )

    def renderNewData( self, inv, data ):
        render = { "fallback" : "Reporting new data.",
                   "pretext" : "Reporting new data: `%s`." % data[ 'why' ],
                   "mrkdwn_in": [ "text", "pretext" ] }
        if 0 != len( data[ 'data' ] ):
            render[ "text" ] = self.prettyJson( data[ 'data' ] )
        return self.sanitizeJson( render )

    def renderInvConclusion( self, inv ):
        render = { "fallback" : "Investigation concluded on %s." % inv[ 'closed' ],
                   "pretext" : "Investigation concluded,",
                   "author_name" : inv[ 'hunter' ],
                   "mrkdwn_in": [ "text", "pretext" ],
                   "fields" : [ { "title" : "Reasoning", "value" : inv[ 'why' ], "short" : True },
                                { "title" : "Nature", "value" : InvestigationNature.lookup[ inv[ 'nature' ] ], "short" : True },
                                { "title" : "Conclusion", "value" : InvestigationConclusion.lookup[ inv[ 'conclusion' ] ], "short" : True },
                                { "title" : "Closed On", "value" : inv[ 'closed' ], "short" : True } ] }
        return self.sanitizeJson( render )

    def newInvestigation( self, sources, investigation ):
        hostNames = [ self.getHostname( x ) for x in sources ]
        channelName = '#inv_%s' % ( investigation[ 'inv_id' ][ : 8 ] )
        self.makeChannel( channelName )
        self.inviteToChannel( channelName )

        self.slack.chat.post_message( channelName, attachments = [ self.renderInvHeader( investigation, sources ) ] )

        for evt in sorted( investigation[ 'data' ] + investigation[ 'tasks' ], key = lambda x: x[ 'generated' ] ):
            if evt.get( 'sent', None ) is not None:
                self.slack.chat.post_message( channelName, attachments = [ self.renderNewTasking( investigation, evt )] )
            else:
                self.slack.chat.post_message( channelName, attachments = [ self.renderNewData( investigation, evt )] )

        self.slack.chat.post_message( channelName, attachments = [ self.renderInvConclusion( investigation ) ] )

        if investigation[ 'nature' ] in ( InvestigationNature.FALSE_POSITIVE, InvestigationNature.DUPLICATE ):
            self.archiveChannel( channelName )

    def task( self, ctx, dest, cmdsAndArgs ):
        ret = None
        if type( cmdsAndArgs[ 0 ] ) not in ( tuple, list ):
            cmdsAndArgs = ( cmdsAndArgs, )
        if not self.isSensorAllowed( ctx, dest ): return
        data = { 'dest' : dest, 'tasks' : cmdsAndArgs }

        # Currently Hunters only operate live
        data[ 'expiry' ] = 0
        trxId = '%s//%s' % ( self.invId, self.taskId )
        self.taskId += 1
        data[ 'inv_id' ] = trxId

        # We start listening for an answer before sending the tasking
        # so that we are sure to beat the race in case an answer comes
        # back really quickly.
        ret = _TaskResp( trxId, self.actor )

        def _syncRecv( msg ):
            routing, event, mtd = msg.data
            ret._add( event )
            return ( True, )

        self.actor.handle( trxId, _syncRecv )

        resp = self.actor.tasking.request( 'task', data, key = dest, timeout = 30, nRetries = 0 )
        if resp.isSuccess:
            msg = "sent for tasking: %s" % ( str(cmdsAndArgs), )
            self.actor.log( msg )
            self.slack.chat.post_message( ctx.channel, msg )
        else:
            if 'usage' == resp.error:
                msg = "```%s```" % resp.data
            else:
                msg = "failed to send tasking: ```%s```" % resp
            self.actor.log( msg )
            self.slack.chat.post_message( ctx.channel, msg )
            # Well we listened for nothing, cleanup.
            ret.done()
            ret = None

        return ret

    def getSingleAtom( self, id ):
        resp = self.actor.model.request( 'get_atoms_from_root', { 'id' : id, 'depth' : 0 } )
        if resp.isSuccess and 0 < len( resp.data ):
            return resp.data[ 0 ]
        else:
            return None

    def getChildrenAtoms( self, id, depth = 5 ):
        resp = self.actor.model.request( 'get_atoms_from_root', { 'id' : id, 'depth' : depth } )
        if resp.isSuccess:
            return resp.data
        else:
            return None

    # This is a generator
    def crawlUpParentTree( self, rootEvent, rootAtom = None ):
        currentEvent = rootEvent
        while True:
            if currentEvent is None and rootAtom is not None:
                parentAtom = rootAtom
            else:
                parentAtom = _x_( currentEvent, '?/hbs.PARENT_ATOM' )
            if parentAtom is None:
                return
            parentEvent = self.getSingleAtom( parentAtom )
            if parentEvent is None:
                return
            currentEvent = parentEvent
            yield parentEvent