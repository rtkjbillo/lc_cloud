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
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )
_x_ = Actor.importLib( 'utils/hcp_helpers', '_x_' )
InvestigationNature = Actor.importLib( 'utils/hcp_helpers', 'InvestigationNature' )
InvestigationConclusion = Actor.importLib( 'utils/hcp_helpers', 'InvestigationConclusion' )

class SlackRep( Actor ):
    def init( self, parameters, resources ):
        self.channel_allDetects = parameters.get( 'channel_all_detects', 'all_detects' )

        self.audit = self.getActorHandle( resources[ 'auditing' ] )
        self.model = self.getActorHandle( resources[ 'modeling' ] )
        self.deployment = self.getActorHandle(( resources[ 'deployment' ] ) )
        self.identManager = self.getActorHandle( resources[ 'identmanager' ] )

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
                        self.reps[ oid ] = RepInstance( self, oToken, botToken )

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

class RepInstance( object ):
    def __init__( self, actor, apiToken, botToken ):
        self.actor = actor
        self.apiToken = apiToken
        self.botToken = botToken
        self.slack = Slacker( self.apiToken )
        self.bot = SlackClient( self.botToken )
        self.botId = None

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
            self.bot.rtm_send_message( '#general', '%s reporting in.' % ( self.bot.server.username, ) )

            while not stopEvent.wait( 1.0 ):
                for slackMessage in self.bot.rtm_read():
                    message = slackMessage.get( 'text' )
                    fromUser = slackMessage.get( 'user' )
                    channel = slackMessage.get( 'channel' )
                    if not message or not fromUser or ( '<@%s>' % self.botId ) not in message:
                        continue
                    self.executeCommand( channel, fromUser, shlex.split( message.replace( '<@%s>' % self.botId, '' ) ) )

        except:
            import traceback
            self.actor.log( "Excp: %s" % traceback.format_exc() )

        self.actor.log( "bot terminating" )

    def executeCommand( self, channel, user, cmd ):
        self.bot.rtm_send_message( channel, 'so %s wants me to %s' % ( user, str( cmd ) ) )

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

    def msTsToTime( self, ts ):
        if type( ts ) in ( str, unicode ):
            ts = ts.split( '.' )[ 0 ]
        return datetime.datetime.fromtimestamp( float( ts ) / 1000 ).strftime( '%Y-%m-%d %H:%M:%S.%f' )

    def newDetect( self, sources, detect ):
        hostNames = [ self.getHostname( x ) for x in sources ]
        atom = _x_( detect[ 'detect' ], '?/hbs.THIS_ATOM' )
        message = [ 'Detected *%s* on *%s*:' % ( detect[ 'cat' ], ', '.join( hostNames ) ) ]
        message.append( 'Summary: %s.' % detect[ 'summary' ] )
        message.append( 'Link to sensor: %s' % ' '.join( [ ( '%s/sensor?sid=%s' % ( self.actor.uiDomain, x.sensor_id ) ) for x in sources ] ) )
        if atom is not None:
            message.append( 'Link to event: %s/explore?atid=%s' % ( self.actor.uiDomain, uuid.UUID( bytes = atom ) ) )
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
                    message.append( '```%s```' % json.dumps( self.sanitizeJson( evt[ 'data' ] ), indent = 2 ) )
            self.slack.chat.post_message( channelName, '\n'.join( message ) )
        message = [ '*Closed* on %s' % ( investigation[ 'closed' ] ),
                    '*Why*: %s' % investigation[ 'why' ],
                    '*Nature*: %s' % ( InvestigationNature.lookup[ investigation[ 'nature' ] ], ),
                    '*Conclusion*: %s' % ( InvestigationConclusion.lookup[ investigation[ 'conclusion' ] ], ) ]
        self.slack.chat.post_message( channelName, '\n'.join( message ) )

        if investigation[ 'nature' ] in ( InvestigationNature.FALSE_POSITIVE, InvestigationNature.DUPLICATE ):
            self.archiveChannel( channelName )