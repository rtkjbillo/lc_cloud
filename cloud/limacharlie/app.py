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
def tsToTime( ts ):
    return datetime.datetime.fromtimestamp( int( ts ) ).strftime( '%Y-%m-%d %H:%M:%S' )

def timeToTs( timeStr ):
    return time.mktime( datetime.datetime.strptime( timeStr, '%Y-%m-%d %H:%M:%S' ).timetuple() )

def _xm_( o, path, isWildcardDepth = False ):
    def _isDynamicType( e ):
        eType = type( e )
        return issubclass( eType, dict ) or issubclass( eType, list ) or issubclass( eType, tuple )

    def _isListType( e ):
        eType = type( e )
        return issubclass( eType, list ) or issubclass( eType, tuple )

    def _isSeqType( e ):
        eType = type( e )
        return issubclass( eType, dict )

    result = []
    oType = type( o )

    if type( path ) is str or type( path ) is unicode:
        tokens = [ x for x in path.split( '/' ) if x != '' ]
    else:
        tokens = path

    if issubclass( oType, dict ):
        isEndPoint = False
        if 0 != len( tokens ):
            if 1 == len( tokens ):
                isEndPoint = True

            curToken = tokens[ 0 ]

            if '*' == curToken:
                if 1 < len( tokens ):
                    result = _xm_( o, tokens[ 1 : ], True )
            elif '?' == curToken:
                if 1 < len( tokens ):
                    result = []
                    for elem in o.itervalues():
                        if _isDynamicType( elem ):
                            result += _xm_( elem, tokens[ 1 : ], False )

            elif o.has_key( curToken ):
                if isEndPoint:
                    result = [ o[ curToken ] ] if not _isListType( o[ curToken ] ) else o[ curToken ]
                elif _isDynamicType( o[ curToken ] ):
                    result = _xm_( o[ curToken ], tokens[ 1 : ] )

            if isWildcardDepth:
                tmpTokens = tokens[ : ]
                for elem in o.itervalues():
                    if _isDynamicType( elem ):
                        result += _xm_( elem, tmpTokens, True )
    elif issubclass( oType, list ) or oType is tuple:
        result = []
        for elem in o:
            if _isDynamicType( elem ):
                result += _xm_( elem, tokens )

    return result

def _x_( o, path, isWildcardDepth = False ):
    r = _xm_( o, path, isWildcardDepth )
    if 0 != len( r ):
        r = r[ 0 ]
    else:
        r = None
    return r

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
            return json.dumps( r )
        except:
            return json.dumps( { 'error' : str( r ) } )
    return wrapped

###############################################################################
# PAGES
###############################################################################
class Index:
    def GET( self ):
        return render.index()

class Dashboard:
    def GET( self ):

        sensors = model.request( 'list_sensors', {} )

        if not sensors.isSuccess:
            return render.error( str( sensors ) )

        return render.dashboard( sensors = sensors.data )

class Sensor:
    def GET( self ):
        params = web.input( sensor_id = None, before = None, after = None, max_size = '4096', per_page = '10' )

        if params.sensor_id is None:
            return render.error( 'sensor_id required' )

        info = model.request( 'get_sensor_info', { 'id_or_host' : params.sensor_id } )

        if not info.isSuccess:
            return render.error( str( info ) )

        if 0 == len( info.data ):
            return render.error( 'Sensor not found' )

        before = None
        after = None

        if '' != params.before:
            before = params.before
        if '' != params.after:
            after = params.after

        return render.sensor( info.data[ 'id' ], before, after, params.max_size, params.per_page )

class SensorState:
    @jsonApi
    def GET( self ):
        params = web.input( sensor_id = None )

        if params.sensor_id is None:
            raise web.HTTPError( '400 Bad Request: sensor id required' )

        info = model.request( 'get_sensor_info', { 'id_or_host' : params.sensor_id } )

        if not info.isSuccess:
            raise web.HTTPError( '503 Service Unavailable: %s' % str( info ) )

        if 0 == len( info.data ):
            raise web.HTTPError( '204 No Content: sensor not found' )

        return info.data

class Timeline:
    @jsonApi
    def GET( self ):
        params = web.input( sensor_id = None, after = None, before = None, max_size = '4096', rich = 'false' )

        if params.sensor_id is None:
            raise web.HTTPError( '400 Bad Request: sensor id required' )

        if params.after is None or '' == params.after:
            raise web.HTTPError( '400 Bad Request: need start time' )

        start_time = int( params.after )
        max_size = int( params.max_size )
        rich = True if params.rich == 'true' else False

        if 0 == start_time:
            start_time = int( time.time() ) - 5

        req = { 'id' : params.sensor_id,
                'is_include_content' : True,
                'after' : start_time }

        if not rich:
            req[ 'max_size' ] = max_size

        if params.before is not None and '' != params.before:
            req[ 'before' ] = int( params.before )

        info = model.request( 'get_timeline', req )

        if not info.isSuccess:
            return render.error( str( info ) )

        if 0 == int( params.after ):
            info.data[ 'new_start' ] = start_time

        if rich:
            originalEvents = info.data.get( 'events', [] )
            info.data[ 'events' ] = []
            for event in originalEvents:
                richEvent = None
                if hasattr( eventRender, event[ 1 ] ):
                    try:
                        richEvent = str( getattr( eventRender, event[ 1 ] )( event[ 3 ] ) )
                    except:
                        richEvent = None
                if richEvent is None:
                    richEvent = str( eventRender.default( event[ 3 ] ) )

                info.data[ 'events' ].append( ( event[ 0 ],
                                                event[ 1 ],
                                                event[ 2 ],
                                                richEvent ) )
        return info.data

class ObjSearch:
    def GET( self ):
        params = web.input( objname = None )

        if params.objname is None:
            return render.error( 'Must specify an object name' )

        objects = model.request( 'get_obj_list', { 'name' : params.objname } )

        if not objects.isSuccess:
            return render.error( str( objects ) )

        return render.objlist( objects.data[ 'objects' ], None )

class ObjViewer:
    def GET( self ):
        params = web.input( sensor_id = None, id = None )

        if params.id is None:
            return render.error( 'need to supply an object id' )

        req = { 'id' : params.id }

        if params.sensor_id is not None:
            req[ 'host' ] = params.sensor_id

        info = model.request( 'get_obj_view', req )

        if not info.isSuccess:
            return render.error( str( info ) )

        return render.obj( info.data, params.sensor_id )

class LastEvents:
    @jsonApi
    def GET( self ):
        params = web.input( sensor_id = None )

        if params.sensor_id is None:
            raise web.HTTPError( '400 Bad Request: sensor id required' )

        info = model.request( 'get_lastevents', { 'id' : params.sensor_id } )

        if not info.isSuccess:
            raise web.HTTPError( '503 Service Unavailable : %s' % str( info ) )

        return info.data.get( 'events', [] )

class EventView:
    def GET( self ):
        params = web.input( id = None )

        if params.id is None:
            return render.error( 'need to supply an event id' )

        info = model.request( 'get_event', { 'id' : params.id } )

        if not info.isSuccess:
            return render.error( str( info ) )

        return render.event( info.data.get( 'event', {} ) )

class HostObjects:
    def GET( self ):
        params = web.input( sensor_id = None, otype = None )

        if params.sensor_id is None:
            return render.error( 'need to supply a sensor id' )

        req = { 'host' : params.sensor_id }

        if params.otype is not None:
            req[ 'type' ] = params.otype

        objects = model.request( 'get_obj_list', req )

        return render.objlist( objects.data[ 'objects' ], params.sensor_id )

class JsonDetects:
    @jsonApi
    def GET( self ):
        params = web.input( before = None, after = None )

        if params.after is None or '' == params.after:
            raise web.HTTPError( '400 Bad Request: start time required' )

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
            return render.error( str( detects ) )
        else:
            return detects.data

class ViewDetects:
    def GET( self ):
        params = web.input( before = None, after = None )

        before = None
        after = None

        if params.before is not None and '' != params.before:
            before = params.before
        if params.after is not None and '' != params.after:
            after = params.after

        return render.detects( before, after )

class ViewDetect:
    def GET( self ):
        params = web.input( id = None )

        if params.id is None:
            return render.error( 'need to supply a detect id' )

        info = model.request( 'get_detect', { 'id' : params.id, 'with_events' : True } )

        if not info.isSuccess:
            return render.error( str( info ) )

        return render.detect( info.data.get( 'detect', [] ) )

class HostChanges:
    @jsonApi
    def GET( self ):
        params = web.input( sensor_id = None )

        if params.sensor_id is None:
            raise web.HTTPError( '400 Bad Request: sensor id required' )

        info = model.request( 'get_host_changes', { 'id' : params.sensor_id } )

        if not info.isSuccess:
            raise web.HTTPError( '503 Service Unavailable : %s' % str( info ) )

        return info.data.get( 'changes', {} )

###############################################################################
# BOILER PLATE
###############################################################################
os.chdir( os.path.dirname( os.path.abspath( __file__ ) ) )

urls = ( r'/', 'Index',
         r'/dashboard', 'Dashboard',
         r'/sensor', 'Sensor',
         r'/search', 'Search',
         r'/sensor_state', 'SensorState',
         r'/timeline', 'Timeline',
         r'/objsearch', 'ObjSearch',
         r'/obj', 'ObjViewer',
         r'/lastevents', 'LastEvents',
         r'/event', 'EventView',
         r'/hostobjects', 'HostObjects',
         r'/detects_data', 'JsonDetects',
         r'/detects', 'ViewDetects',
         r'/detect', 'ViewDetect',
         r'/hostchanges', 'HostChanges' )

web.config.debug = False
app = web.application( urls, globals() )

render = web.template.render( 'templates', base = 'base', globals = { 'json' : json,
                                                                      'tsToTime' : tsToTime,
                                                                      '_x_' : _x_,
                                                                      '_xm_' : _xm_,
                                                                      'hex' : hex } )
eventRender = web.template.render( 'templates/custom_events', globals = { 'json' : json,
                                                                          'tsToTime' : tsToTime,
                                                                          '_x_' : _x_,
                                                                          '_xm_' : _xm_,
                                                                          'hex' : hex } )

if len( sys.argv ) < 2:
    print( "Usage: python app.py beach_config [listen_port]" )
    sys.exit()

beach = Beach( sys.argv[ 1 ], realm = 'hcp' )
del( sys.argv[ 1 ] )
model = beach.getActorHandle( 'models', nRetries = 3, timeout = 30, ident = 'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903' )

app.run()