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

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
CreateOnAccess = Actor.importLib( 'utils/hcp_helpers', 'CreateOnAccess' )

class PagingActor( Actor ):
    def init( self, parameters, resources ):
        self.deploymentManager = CreateOnAccess( self.getActorHandle, resources[ 'deployment' ] )
        self.fromAddr = parameters.get( 'from', None )
        self.user = parameters.get( 'user', None )
        self.password = parameters.get( 'password', None )
        self.smtpServer = parameters.get( 'smtp_server', 'smtp.gmail.com' )
        self.smtpPort = parameters.get( 'smtp_port', '587' )
        if self.user is None:
            self.refreshCredentials()
            self.log( 'got credentials from deployment manager' )
        else:
            self.log( 'got credentials from parameters' )

        if self.user is None or self.password is None:
            self.logCritical( 'missing user or password' )

        self.handle( 'page', self.page )

    def deinit( self ):
        pass

    def refreshCredentials( self ):
        resp = self.deploymentManager.request( 'get_global_config', {} )
        if resp.isSuccess:
            self.fromAddr = resp.data[ 'global/paging_from' ]
            self.user = resp.data[ 'global/paging_user' ]
            self.password = resp.data[ 'global/paging_password' ]
            if '' == self.user:
                self.user = None
            if '' == self.password:
                self.password = None
            if '' == self.fromAddr:
                self.fromAddr = None
        self.delay( 60, self.refreshCredentials )

    def page( self, msg ):
        if self.fromAddr is None or self.password is None: return ( False, )
        toAddr = msg.data.get( 'to', None )
        message = msg.data.get( 'msg', None )
        subject = msg.data.get( 'subject', None )

        if toAddr is not None and message is not None and subject is not None:
            self.log( "Paging %s" % toAddr )
            self.sendPage( toAddr, subject, message )
            self.zInc( "n_sent" )
            return ( True, )
        else:
            return ( False, )

    def sendPage( self, dest, subject, message ):
        if type( dest ) is str or type( dest ) is unicode:
            dest = ( dest, )
        msg = MIMEMultipart( 'alternative' )
        dest = ', '.join( dest )
        content_text = message
        content_html = message.replace( '\n', '<br/>' ).replace( ' ', '&nbsp;' ).replace( '\t', '&nbsp;&nbsp;' )

        msg[ 'To' ] = dest
        msg[ 'From' ] = self.fromAddr if self.fromAddr is not None else self.user
        msg[ 'Subject' ] = subject
        msg.attach( MIMEText( content_text, 'plain' ) )
        msg.attach( MIMEText( content_html, 'html' ) )

        smtp = smtplib.SMTP( self.smtpServer, self.smtpPort )
        smtp.ehlo()
        smtp.starttls()
        smtp.login( self.user, self.password )
        smtp.sendmail( self.user, dest, msg.as_string() )
