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
_x_ = Actor.importLib( '../hcp_helpers', '_x_' )
_xm_ = Actor.importLib( '../hcp_helpers', '_xm_' )

import logging
import logging.handlers

class CEFOutput( Actor ):
    def init( self, parameters ):
        self._logger = logging.getLogger( 'limacharlie_cef' )
        self._logger.setLevel( logging.INFO )
        self._logger.addHandler( logging.handlers.SysLogHandler( address = parameters.get( 'url', '127.0.0.1' ),
                                                                 facility = logging.handler.SysLogHandler.LOG_LOCAL4 ) )

        self.handle( 'report', self.report )
        
    def deinit( self ):
        pass

    def report( self, msg ):
        event_ids = msg.data[ 'msg_ids' ]
        category = msg.data[ 'cat' ]
        source = msg.data[ 'source' ]
        detect = msg.data[ 'detect' ]
        report_id = msg.data[ 'report_id' ].upper()
        summary = msg.data[ 'summary' ]
        priority = msg.data[ 'priority' ]

        record = 'CEF:0|refractionPOINT|LimaCharlie|1|%s|%s|%s|' % ( category, summary, priority )
        extension = { 'refractionPOINTLimaCharlieFullDetails' : detect }

        # Try to parse out common datatypes
        # For now we'll only populate the details.

        for k, v in extension.iteritems():
            v = unicode( v )
            record += '%s=%s ' % ( k, v.replace( r'\\', r'\\\\' )
                                       .replace( r'=', r'\=' )
                                       .replace( '\r\n', r'\r\n' )
                                       .replace( '\n', r'\n' ) )

        record = record.encode( 'utf-8' )

        self._logger.info( record )

        return ( True, )