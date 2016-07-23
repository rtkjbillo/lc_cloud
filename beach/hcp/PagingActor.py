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

class PagingActor( Actor ):
    def init( self, parameters, resources ):
        self.fromAddr = parameters.get( 'from', None )
        self.password = parameters.get( 'password', None )
        self.smtpServer = parameters.get( 'smtp_server', 'smtp.gmail.com' )
        self.smtpPort = parameters.get( 'smtp_port', '587' )
        self.handle( 'page', self.page )
        if self.fromAddr is None or self.password is None:
            self.logCritical( 'missing user or password' )

    def deinit( self ):
        pass

    def page( self, msg ):
        if self.fromAddr is None or self.password is None: return ( True, )
        toAddr = msg.data.get( 'to', None )
        message = msg.data.get( 'msg', None )
        subject = msg.data.get( 'subject', None )

        if toAddr is not None and message is not None and subject is not None:
            self.sendPage( toAddr, subject, message )
            return ( True, )
        else:
            return ( False, )

    def sendPage( self, dest, subject, message ):
        if type( dest ) is str or type( dest ) is unicode:
            dest = ( dest, )
        msg = MIMEMultipart( 'alternative' )
        dest = ', '.join( dest )
        content_text = message
        content_html = message.replace( '\n', '<br/>' )

        msg[ 'To' ] = dest
        msg[ 'From' ] = self.fromAddr
        msg[ 'Subject' ] = subject
        msg.attach( MIMEText( content_text, 'plain' ) )
        msg.attach( MIMEText( content_html, 'html' ) )

        smtp = smtplib.SMTP( self.smtpServer, self.smtpPort )
        smtp.ehlo()
        smtp.starttls()
        smtp.login( self.fromAddr, self.password )
        smtp.sendmail( self.fromAddr, dest, msg.as_string() )
