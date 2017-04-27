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
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )
_x_ = Actor.importLib( 'utils/hcp_helpers', '_x_' )
InvestigationNature = Actor.importLib( 'utils/hcp_helpers', 'InvestigationNature' )
InvestigationConclusion = Actor.importLib( 'utils/hcp_helpers', 'InvestigationConclusion' )
ObjectTypes = Actor.importLib( 'utils/ObjectsDb', 'ObjectTypes' )
Event = Actor.importLib( 'utils/hcp_helpers', 'Event' )

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

        self.audit = self.getActorHandle( resources[ 'auditing' ] )
        self.model = self.getActorHandle( resources[ 'modeling' ] )
        self.deployment = self.getActorHandle(( resources[ 'deployment' ] ) )
        self.identManager = self.getActorHandle( resources[ 'identmanager' ] )
        self.sensordir = self.getActorHandle( resources[ 'sensordir' ] )
        self.tasking = self.getActorHandle( resources[ 'autotasking' ] )
        self.huntmanager = self.getActorHandle( resources[ 'huntsmanager' ] )

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
            self.bot.rtm_send_message( '#general', 'Reporting in.' )

            while not stopEvent.wait( 1.0 ):
                for slackMessage in self.tryToRead():
                    message = slackMessage.get( 'text' )
                    fromUser = slackMessage.get( 'user' )
                    channel = slackMessage.get( 'channel' )
                    if not message or not fromUser or ( '<@%s>' % self.botId ) not in message:
                        continue
                    ctx = CommandContext( channel, 
                                          fromUser, 
                                          [ self.stripSlackFormatting( x ) for x in shlex.split( message.replace( '<@%s>' % self.botId, '' ) ) ], 
                                          copy.deepcopy( self.history ) )
                    self.actor.newThread( self.executeCommand, ctx )

        except:
            self.actor.log( "Excp: %s" % traceback.format_exc() )
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
            self.actor.log( "CMD: %s" % str(ctx.cmd) )
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
            else:
                self.bot.rtm_send_message( ctx.channel, "what are you talking about, need *help*?" )
        except:
            self.bot.rtm_send_message( ctx.channel, "oops I've fallen and I can't get up: %s" % ( traceback.format_exc(), ) )
            self.actor.log( "Excp: %s" % traceback.format_exc() )

        self.history[ 'last_cmd' ] = ctx.cmd

    def sendHelp( self, ctx ):
        self.bot.rtm_send_message( ctx.channel, self.prettyJson( 
        {
            'help' : 'this help',
            '?' : [ '? <object_name>: lists the objects of any types with that name',
                    '? <object_name> <object_type> . [of_type]: lists the locations where the object was seen',
                    '? <object_name> <object_type> > [of_type]: lists all the parents of the object',
                    '? <object_name> <object_type> < [of_type}: lists all the children of the object' ],
            '!' : [ '! sensor_id command [arguments...]: execute the command on the sensor, investigation sensor if sensor id not specified' ],
            '>' : [ '> atom_id: get the parent event of the atom id or atom id of the 1-based index in the previous command result' ],
            '<' : [ '< atom_id: get the children events of the atom id or atom id of the 1-based index in the previous command result' ],
            '.' : [ '. [hostname | sensor_id]: get information on a host by name or sensor id' ]
        } ) )

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
        for info in topTraffic:
            output.append( '  *%s* bytes: *%s* (%s) since *%s*' % ( info[ 0 ], self.getHostname( info[ 2 ] ), info[ 2 ], self.sTsToTime( info[ 1 ] ) ) )
        
        self.bot.rtm_send_message( ctx.channel, "\n".join( output ) )

    def command_task( self, ctx ):
        taskFuture = self.task( ctx, ctx.cmd[ 1 ], ctx.cmd[ 2 : ] )
        if taskFuture is not None:
            try:
                if taskFuture.wait( 60 ):
                    start = time.time()
                    while time.time() < start + 30:
                        try:
                            resp = taskFuture.responses.pop()
                            data = self.prettyJson( resp )
                            if 512 < len( data ):
                                atom = base64.b64decode( _x_( resp, '?/hbs.THIS_ATOM' ) )
                                self.slack.chat.post_message( ctx.channel,
                                                              'the response is large (%s bytes) get it at: %s/explore?atid=%s' % ( len( data ), self.actor.uiDomain, uuid.UUID( bytes = atom ) ) )
                            else:
                                self.slack.chat.post_message( ctx.channel, data )
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
        pass

    def command_children_atom( self, ctx ):
        pass

    def command_host_info( self, ctx ):
        hostOrId = ctx.cmd[ 1 ]
        hostInfo = self.getHostInfo( hostOrId )
        self.bot.rtm_send_message( ctx.channel, "host info for *%s*: %s" % ( ctx.cmd[ 1 ], self.prettyJson( hostInfo ) ) )

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
        elif type( o ) is uuid.UUID:
            o = str( o )
        else:
            try:
                if ( type(o) is str or type(o) is unicode ) and "\x00" in o: raise Exception()
                json.dumps( o )
            except:
                o = base64.b64encode( o )

        return o

    def prettyJson( self, o ):
        return '```%s```' % json.dumps( self.sanitizeJson( o ), indent = 2 )

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
            cid = None
            for channel in self.slack.channels.list().body[ 'channels' ]:
                if name == channel[ 'name' ]:
                    cid = channel[ 'id' ]
                    break
            if cid is not None:
                self.slack.channels.archive( cid )
        except:
            return False
        return True

    def inviteToChannel( self, name ):
        try:
            cid = None
            for channel in self.slack.channels.list().body[ 'channels' ]:
                if name == channel[ 'name' ]:
                    cid = channel[ 'id' ]
                    break
            if cid is not None:
                self.slack.channels.invite( cid, 'limacharlie' )
        except:
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
        message.append( self.prettyJson( detect[ 'detect' ] ) )
        self.slack.chat.post_message( '#detects', '\n'.join( message ) )

    def newInvestigation( self, sources, investigation ):
        hostNames = [ self.getHostname( x ) for x in sources ]
        channelName = '#inv_%s' % ( investigation[ 'inv_id' ][ : 8 ] )
        self.makeChannel( channelName )
        self.inviteToChannel( channelName )

        message = [ '*Created* on %s' % ( investigation[ 'generated' ] ) ]
        self.slack.chat.post_message( channelName, '\n'.join( message ) )

        for evt in sorted( investigation[ 'data' ] + investigation[ 'tasks' ], key = lambda x: x[ 'generated' ] ):
            message = [ 'Hunter: *%s*' % investigation[ 'hunter' ] ]
            ts = self.msTsToTime( evt[ 'generated' ] )
            if evt.get( 'sent', None ) is not None:
                # This is a tasking
                task = ''
                if evt[ 'sent' ] is True:
                    task = '-> '
                else:
                    task = '-x'
                message.append( '%s `%s` @ %s' % ( task, str( evt[ 'data' ] ), ts ) )
                message.append( 'Why: %s' % evt[ 'why' ] )
            else:
                # This is data eval
                message.append( 'Reporting: %s' % evt[ 'why' ] )
                if 0 != len( evt[ 'data' ] ):
                    message.append( self.prettyJson( evt[ 'data' ] ) )
            self.slack.chat.post_message( channelName, '\n'.join( message ) )
        message = [ '*Closed* on %s' % ( investigation[ 'closed' ] ),
                    '*Why*: %s' % investigation[ 'why' ],
                    '*Nature*: %s' % ( InvestigationNature.lookup[ investigation[ 'nature' ] ], ),
                    '*Conclusion*: %s' % ( InvestigationConclusion.lookup[ investigation[ 'conclusion' ] ], ) ]
        self.slack.chat.post_message( channelName, '\n'.join( message ) )

        if investigation[ 'nature' ] in ( InvestigationNature.FALSE_POSITIVE, InvestigationNature.DUPLICATE ):
            self.archiveChannel( channelName )

    def task( self, ctx, dest, cmdsAndArgs ):
        ret = None
        if type( cmdsAndArgs[ 0 ] ) not in ( tuple, list ):
            cmdsAndArgs = ( cmdsAndArgs, )
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
            msg = "failed to send tasking"
            self.actor.log( msg )
            self.slack.chat.post_message( ctx.channel, msg )
            # Well we listened for nothing, cleanup.
            ret.done()
            ret = None

        return ret