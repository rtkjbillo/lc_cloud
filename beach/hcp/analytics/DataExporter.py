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
import uuid
import base64
import time
import msgpack
import zipfile
import StringIO

AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )

class DataExporter( Actor ):
    def init( self, parameters, resources ):
        self.model = self.getActorHandle( resources[ 'models' ], timeout = 600, nRetries = 1 )
        self.audit = self.getActorHandle( resources[ 'auditing' ], timeout = 10, nRetries = 3 )
        self.handle( 'export_sensor', self.exportSensor )
        
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

    def exportSensor( self, msg ):
        oid = uuid.UUID( msg.data[ 'oid' ] )
        byUser = msg.data[ 'by' ]
        isJson = msg.data.get( 'is_json', True )
        isFlat = msg.data.get( 'is_flat', False )
        after = int( msg.data.get( 'after', 0 ) )
        sid = AgentId( msg.data[ 'sid' ] ).sensor_id
        before = int( msg.data.get( 'before', time.time() + 5 ) )

        self.audit.shoot( 'record', { 'oid' : oid, 
                                      'etype' : 'export_sensor', 
                                      'msg' : 'User %s exported sensor data %s ( %s - %s ).' % ( byUser, sid, after, before ) } )

        info = self.model.request( 'get_timeline', { 'id' : sid,
                                                     'is_include_content' : True,
                                                     'after' : after,
                                                     'before' : before,
                                                     'with_routing' : True } )

        if info.isSuccess:
            output = []
            for ts, eType, eId, fullEvent in info.data.get( 'events', [] ):
                routing, event = fullEvent
                record = { 'routing' : routing,
                           'event' : event }
                if isFlat:
                    record = self.flattenRecord( record )
                if isJson:
                    record = json.dumps( record )
                output.append( record )

            if not isJson:
                output = msgpack.packb( output )

            zOutput = StringIO.StringIO()
            exportName = '%s_%s_%s.%s' % ( sid, after, before, ( "json" if isJson else "dat" ) )
            with zipfile.ZipFile( zOutput, 'w', compression = zipfile.ZIP_DEFLATED ) as zf:
                if not isJson:
                    zf.writestr( exportName, output )
                else:
                    zf.writestr( exportName, "\n".join( output ) )

            del( output )

        else:
            return ( True, { 'error' : str( info ) } )

        return ( True, { 'export' : zOutput.getvalue(), 'export_name' : '%s.zip' % ( exportName, ) } )
