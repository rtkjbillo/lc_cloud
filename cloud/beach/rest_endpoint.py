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

import os
import sys

from beach.beach_api import Beach

import traceback
import web
import datetime
import time
import json
from functools import wraps


###############################################################################
# CUSTOM EXCEPTIONS
###############################################################################


###############################################################################
# REFERENCE ELEMENTS
###############################################################################


###############################################################################
# CORE HELPER FUNCTIONS
###############################################################################
def raiseBadRequest( error ):
    raise web.HTTPError( '400 Bad Request: %s' % error )

def raiseUnavailable( error ):
    raise web.HTTPError( '503 Service Unavailable: %s' % error )

###############################################################################
# PAGE DECORATORS
###############################################################################
def jsonApi( f ):
    ''' Decorator to basic exception handling on function. '''
    @wraps( f )
    def wrapped( *args, **kwargs ):
        web.header( 'Content-Type', 'application/json' )
        r = f( *args, **kwargs )
        try:
            return json.dumps( r, indent = 2 )
        except:
            return json.dumps( { 'error' : str( r ) } )
    return wrapped

###############################################################################
# PAGES
###############################################################################
class Index:
    @jsonApi
    def GET( self ):
        return { 'api' : 'limacharlie/general', 'version' : 1,
                 'usage' : { '/sensorstate' : { 'sensor_id' : 'the 4-tuple of the sensor id OR hostname to lookup' },
                             '/timeline' : { 'sensor_id' : 'the 4-tuple of the sensor',
                                             'after' : 'timestamp of the earliest event times',
                                             'before' : 'timestamp of the latest event times',
                                             'max_size' : 'maximum size of the events to return, default 4096' },
                             '/lastevents' : { 'sensor_id' : '4-tuple of the sensor to lookup' },
                             '/detects' : { 'after' : 'timestamp of the earliest detect',
                                            'before' : 'timestamp of the latest detect' },
                             '/hostchanges' : { 'sensor_id' : '4-tuple of the sensor to get recent changes of' },
                             '/objectloc' : { 'obj_name' : 'the name of the object to lookup',
                                              'obj_type' : 'the type of the object to lookup' } } }

class SensorState:
    @jsonApi
    def GET( self ):
        params = web.input( sensor_id = None )

        if params.sensor_id is None:
            raiseBadRequest( '"sensor_id" required' )

        info = model.request( 'get_sensor_info', { 'id_or_host' : params.sensor_id } )

        if not info.isSuccess:
            raiseUnavailable( str( info ) )

        return info.data

class Timeline:
    @jsonApi
    def GET( self ):
        params = web.input( sensor_id = None, after = None, before = None, max_size = '4096' )

        if params.sensor_id is None:
            raiseBadRequest( '"sensor_id" required' )

        if params.after is None or '' == params.after:
            raiseBadRequest( '"after" required' )

        start_time = int( params.after )
        max_size = int( params.max_size )

        if 0 == start_time:
            start_time = int( time.time() ) - 5

        req = { 'id' : params.sensor_id,
                'is_include_content' : True,
                'after' : start_time,
                'max_size' : max_size }

        if params.before is not None and '' != params.before:
            req[ 'before' ] = int( params.before )

        info = model.request( 'get_timeline', req )

        if not info.isSuccess:
            raiseUnavailable( str( info ) )

        return info.data

class LastEvents:
    @jsonApi
    def GET( self ):
        params = web.input( sensor_id = None )

        if params.sensor_id is None:
            raiseBadRequest( '"sensor_id" required' )

        info = model.request( 'get_lastevents', { 'id' : params.sensor_id } )

        if not info.isSuccess:
            raiseUnavailable( str( info ) )

        return info.data.get( 'events', [] )

class Detects:
    @jsonApi
    def GET( self ):
        params = web.input( before = None, after = None )

        if params.after is None or '' == params.after:
            raiseBadRequest( '"after" required' )

        start_time = None
        if params.after is not None:
            start_time = int( params.after )

        if start_time is None or 0 == start_time:
            start_time = int( time.time() ) - 5

        search = {}

        if start_time is not None:
            search [ 'after' ] = start_time

        if params.before is not None:
            search[ 'before' ] = int( params.before )

        detects = model.request( 'get_detects', search )

        if not detects.isSuccess:
            raiseUnavailable( str( detects ) )

        return detects.data

class HostChanges:
    @jsonApi
    def GET( self ):
        params = web.input( sensor_id = None )

        if params.sensor_id is None:
            raiseBadRequest( '"sensor_id" required' )

        info = model.request( 'get_host_changes', { 'id' : params.sensor_id } )

        if not info.isSuccess:
            raiseUnavailable( str( info ) )

        return info.data.get( 'changes', {} )

class ObjectLocation:
    @jsonApi
    def GET( self ):
        params = web.input( obj_name = None, obj_type = None )
        print( params )
        if( params.obj_name is None or params.obj_name == '' or
            params.obj_type is None or params.obj_type == '' ):
            raiseBadRequest( '"obj_name" and "obj_type" required' )

        objects = [ ( params.obj_name, params.obj_type ) ]

        info = model.request( 'get_obj_loc', { 'objects' : objects } )

        if not info.isSuccess:
            raiseUnavailable( str( info ) )

        return info.data

###############################################################################
# BOILER PLATE
###############################################################################
os.chdir( os.path.dirname( os.path.abspath( __file__ ) ) )

urls = ( r'/', 'Index',
         r'/sensorstate', 'SensorState',
         r'/timeline', 'Timeline',
         r'/lastevents', 'LastEvents',
         r'/detects', 'Detects',
         r'/hostchanges', 'HostChanges',
         r'/objectloc', 'ObjectLocation' )

web.config.debug = False
app = web.application( urls, globals() )

if len( sys.argv ) < 2:
    print( "Usage: python app.py beach_config [listen_port]" )
    sys.exit()

beach = Beach( sys.argv[ 1 ], realm = 'hcp' )
del( sys.argv[ 1 ] )
model = beach.getActorHandle( 'models',
                              nRetries = 3,
                              timeout = 30,
                              ident = 'rest/be41bb0f-449a-45e9-87d8-ef4533336a2d' )

app.run()