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

import os
import json
import logging
import logging.handlers
import uuid
import base64

class FileEventsOutput( Actor ):
    def init( self, parameters ):
        self._output_dir = parameters.get( 'output_dir', '/tmp/lc_out/' )
        if not os.path.exists( self._output_dir ):
            self.log( 'output directory does not exist, creating it' )
            os.makedirs( self._output_dir )
        elif not os.path.isdir( self._output_dir ):
            self.logCritical( 'output_dir exists but is not a directory: %s' % self._output_dir )
            return
        self._file_logger = logging.getLogger( 'limacharlie_events_file' )
        handler = logging.handlers.RotatingFileHandler( os.path.join( self._output_dir, self.name ), 
                                                        maxBytes = 1024 * 1024 * 10, 
                                                        backupCount = 3 )
        handler.setFormatter( logging.Formatter( "%(message)s" ) )
        self._file_logger.setLevel( logging.INFO )
        self._file_logger.addHandler( handler )
        self.handle( 'log', self.logToDisk )
        
    def deinit( self ):
        pass

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

    def logToDisk( self, msg ):
        routing, event, mtd = msg.data
        
        self._file_logger.info( json.dumps( { 'routing' : routing, 
                                              'event' : self.sanitizeJson( event ) } ) )

        return ( True, )