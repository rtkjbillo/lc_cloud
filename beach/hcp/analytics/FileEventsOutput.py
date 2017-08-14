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
    def init( self, parameters, resources ):
        self._output_dir = parameters.get( 'output_dir', '/tmp/lc_out/' )
        self._is_flat = parameters.get( 'is_flat', False )
        if not os.path.exists( self._output_dir ):
            self.log( 'output directory does not exist, creating it' )
            os.makedirs( self._output_dir )
        elif not os.path.isdir( self._output_dir ):
            self.logCritical( 'output_dir exists but is not a directory: %s' % self._output_dir )
            return
        self._file_logger = logging.getLogger( 'limacharlie_events_file' )
        self._file_logger.propagate = False
        handler = logging.handlers.RotatingFileHandler( os.path.join( self._output_dir, self.name ), 
                                                        maxBytes = parameters.get( 'max_bytes', 1024 * 1024 * 10 ), 
                                                        backupCount = parameters.get( 'backup_count', 3 ) )
        handler.setFormatter( logging.Formatter( "%(message)s" ) )
        self._file_logger.setLevel( logging.INFO )
        self._file_logger.addHandler( handler )
        self.handle( 'log', self.logToDisk )
        self.handle( 'report_inv', self.reportDetectOrInv )
        self.handle( 'report_detect', self.reportDetectOrInv )
        
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

    def flattenRecord( self, o, newRoot = None, prefix = '' ):
        isEntry = newRoot is None
        if isEntry: newRoot = {}
        if type( o ) is dict:
            for k, v in o.iteritems():
                if -1 != k.find( '.' ):
                    newK = k[ k.find( '.' ) + 1 : ]
                else:
                    newK = k
                if '' != prefix:
                    newPrefix = '%s/%s' % ( prefix, newK )
                else:
                    newPrefix = newK
                val = self.flattenRecord( v, newRoot, newPrefix )
                if val is not None:
                    newRoot[ newPrefix ] = val
            return newRoot if isEntry else None
        elif type( o ) is list or type( o ) is tuple:
            i = 0
            for v in o:
                newPrefix = '%s_%d' % ( prefix, i )
                val = self.flattenRecord( v, newRoot, newPrefix )
                if val is not None:
                    newRoot[ newPrefix ] = v
                i += 1
            return newRoot if isEntry else None
        else:
            return o

    def logToDisk( self, msg ):
        routing, event, mtd = msg.data

        record = self.sanitizeJson( event )
        if self._is_flat:
            record = self.flattenRecord( record )
        
        self._file_logger.info( json.dumps( { 'routing' : routing, 
                                              'event' : record } ) )

        return ( True, )

    def reportDetectOrInv( self, msg ):
        record = msg.data

        record = self.sanitizeJson( record )
        if self._is_flat:
            record = self.flattenRecord( record )

        self._file_logger.info( json.dumps( record ) )

        return ( True, )