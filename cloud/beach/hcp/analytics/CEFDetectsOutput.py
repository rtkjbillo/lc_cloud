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
_x_ = Actor.importLib( '../utils/hcp_helpers', '_x_' )
_xm_ = Actor.importLib( '../utils/hcp_helpers', '_xm_' )
Host = Actor.importLib( '../utils/ObjectsDb', 'Host' )
BEAdmin = Actor.importLib( '../admin_lib', 'BEAdmin' )

import logging
import logging.handlers

class CEFDetectsOutput( Actor ):
    def init( self, parameters, resources ):
        self.admin = BEAdmin( self._beach_config_path, None )
        Host.setDatabase( self.admin, parameters[ 'scale_db' ] )
        self._cef_logger = logging.getLogger( 'limacharlie_detects_cef' )
        handler = logging.handlers.SysLogHandler( address = parameters.get( 'siem_server', '/dev/log' ) )
        handler.setFormatter( logging.Formatter( "%(message)s" ) )
        self._cef_logger.setLevel( logging.INFO )
        self._cef_logger.addHandler( handler )
        self._lc_web = parameters.get( 'lc_web', '127.0.0.1' )
        self.handle( 'report', self.report )
        
    def deinit( self ):
        Host.closeDatabase()

    def report( self, msg ):
        event_ids = msg.data[ 'msg_ids' ]
        category = msg.data[ 'cat' ]
        source = msg.data[ 'source' ].split( ' / ' )
        detect = msg.data[ 'detect' ]
        detect_id = msg.data[ 'detect_id' ].upper()
        summary = msg.data[ 'summary' ]
        priority = msg.data[ 'priority' ]

        record = 'CEF:0|refractionPOINT|LimaCharlie|1|%s|%s|%s|' % ( category, summary, priority )
        extension = { 'rpLCFullDetails' : detect,
                      'rpLCLink' : 'http://%s/detect?id=%s' % ( self._lc_web, detect_id ),
                      'rpLCHostnames' : ','.join( map( lambda x: Host( x ).getHostName(), source ) ) }

        # Try to parse out common datatypes
        # For now we'll only populate the details.

        for k, v in extension.iteritems():
            v = unicode( v )
            record += '%s=%s ' % ( k, v.replace( r'\\', r'\\\\' )
                                       .replace( r'=', r'\=' )
                                       .replace( '\r\n', r'\r\n' )
                                       .replace( '\n', r'\n' ) )

        record = record.encode( 'utf-8' )

        self._cef_logger.info( record )

        return ( True, )