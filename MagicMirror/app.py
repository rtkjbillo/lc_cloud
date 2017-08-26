# Copyright (C) 2015  refractionPOINT
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import gevent
import gevent.pool
import gevent.monkey
gevent.monkey.patch_all()
import os
import sys

g_current_dir = os.path.dirname( os.path.abspath( __file__ ) )

import traceback
import web
import time
import urllib2
import urllib
import json
import yaml
import msgpack
from functools import wraps
import itertools
import uuid
from collections import OrderedDict

###############################################################################
# CUSTOM EXCEPTIONS
###############################################################################


###############################################################################
# CORE HELPER FUNCTIONS
###############################################################################
def sanitizeJson( o, summarized = False ):
    if type( o ) is dict:
        for k, v in o.iteritems():
            o[ k ] = sanitizeJson( v, summarized = summarized )
    elif type( o ) is list or type( o ) is tuple:
        o = [ sanitizeJson( x, summarized = summarized ) for x in o ]
    else:
        try:
            json.dumps( o )
        except:
            o = base64.b64encode( o )
        if summarized is not False and len( str( o ) ) > summarized:
            o = str( o[ : summarized ] ) + '...'

    return o

class RingCache( object ):
    def __init__( self, maxEntries = 100, isAutoAdd = False ):
        self.max = maxEntries
        self.d = OrderedDict()
        self.isAutoAdd = isAutoAdd
    
    def add( self, k, v = None ):
        if self.max <= len( self.d ):
            self.d.popitem( last = False )
        if k in self.d:
            del( self.d[ k ] )
        self.d[ k ] = v
    
    def get( self, k ):
        return self.d[ k ]
    
    def remove( self, k ):
        del( self.d[ k ] )
    
    def __contains__( self, k ):
        if k in self.d:
            v = self.d[ k ]
            del( self.d[ k ] )
            self.d[ k ] = v
            return True
        else:
            if self.isAutoAdd:
                self.add( k )
            return False
    
    def __len__( self ):
        return len( self.d )
    
    def __repr__( self ):
        return self.d.__repr__()

###############################################################################
# PAGE DECORATORS
###############################################################################
def dumpJson( data ):
    return json.dumps( data, indent = 2 )

def jsonApi( f ):
    ''' Decorator to basic exception handling on function. '''
    @wraps( f )
    def wrapped( *args, **kwargs ):
        web.header( 'Content-Type', 'application/json' )
        r = f( *args, **kwargs )
        try:
            return dumpJson( r )
        except:
            return dumpJson( { 'error' : str( r ) } )
    return wrapped

def msgpackApi( f ):
    ''' Decorator to basic exception handling on function. '''
    @wraps( f )
    def wrapped( *args, **kwargs ):
        web.header( 'Content-Type', 'application/msgpack' )
        r = f( *args, **kwargs )
        try:
            return msgpack.packb( r )
        except:
            return msgpack.packb( { 'error' : str( r ) } )
    return wrapped

def jsonData( data ):
    web.header( 'Content-Type', 'application/json' )
    return dumpJson( data )

def msgpackData( data ):
    web.header( 'Content-Type', 'application/msgpack' )
    return msgpack.packb( data )

def getOrgs():
    orgs = querySites( 'c2/identmanager', 'get_org_info', 
                       queryData = { 'include_all' : True },
                       siteProc = lambda res, ctx, site: dict( [ ( x[ 1 ], x[ 0 ] ) for x in res[ 'orgs' ] ] ), 
                       qProc = lambda res, ctx: reduce( lambda x, y: x.update( y ) or x, res, {} ) )
    return orgs

def firstMatching( results, matcher ):
    for result in results:
        if matcher( result ):
            return result
    return None

def getSiteFor( sid ):
    sensorInfo = querySites( 'models', 'get_sensor_info', 
                             queryData = { 'id_or_host' : sid },
                             siteProc = lambda res, ctx, site: ( res, site ), 
                             qProc = lambda res, ctx: firstMatching( res, lambda x: 0 != len( x[ 0 ] ) ) )
    return sensorInfo

def mergeObj( results ):
    merged = { 'olocs' : [],
               'locs' : {},
               'rlocs' : {},
               'parents' : {},
               'children' : {} }

    for result in results:
        merged[ 'id' ] = result[ 'id' ]
        merged[ 'oname' ] = result[ 'oname' ]
        merged[ 'host' ] = result[ 'host' ]
        merged[ 'otype' ] = result[ 'otype' ]
        merged[ 'olocs' ] += result[ 'olocs' ]
        for parent in result[ 'parents' ]:
            merged[ 'parents' ][ parent[ 0 ] ] = parent
        for child in result[ 'children' ]:
            merged[ 'children' ][ child[ 0 ] ] = child
        for loc, v in result[ 'locs' ].iteritems():
            merged[ 'locs' ].setdefault( loc, 0 )
            merged[ 'locs' ][ loc ] += v
        for k, v in result[ 'rlocs' ].iteritems():
            merged[ 'rlocs' ].setdefault( k, 0 )
            merged[ 'rlocs' ][ k ] += v
    merged[ 'parents' ] = merged[ 'parents' ].values()
    merged[ 'children' ] = merged[ 'children' ].values()

    return merged

###############################################################################
# SITES COMMS
###############################################################################
def defaultSiteProc( result, qContext, site ):
    return result

def defaultQueryProc( results, qContext ):
    return results

def querySite( queryCat, queryAction, queryData, siteProc, site, qContext ):
    qData = { '_format' : 'msgpack', 
              '_ident' : site[ 'ident' ],
              '_timeout' : site[ 'timeout' ],
              '_action' : queryAction }
    if site[ 'secret' ] is not None and '' != site[ 'secret' ]:
        qData[ '_secret' ] = site[ 'secret' ]
    qData[ '_json_data' ] = dumpJson( sanitizeJson( queryData ) )
    u = urllib2.urlopen( '%s/%s' % (site[ 'url' ], queryCat ), urllib.urlencode( qData ) )
    resp = msgpack.unpackb( u.read() )
    u.close()
    return siteProc( resp, qContext, site )

def querySites( queryCat, queryAction, queryData = {}, siteProc = defaultSiteProc, qProc = defaultQueryProc ):
    global sites
    p = gevent.pool.Pool()
    ctx = {}
    
    siteResults = [ x for x in p.imap_unordered( lambda x: querySite( queryCat, queryAction, queryData, siteProc, x, ctx ), sites ) ]
    
    return qProc( siteResults, ctx )


###############################################################################
# PAGES
###############################################################################
class Index:
    @jsonApi
    def GET( self ):
        return urls

class Sites:
    @jsonApi
    def GET( self ):
        global sites
        return sites

class Status:
    @jsonApi
    def GET( self ):
        statuses = {}
        statuses[ 'sensors_online' ] = querySites( 'c2/sensordir', 'get_dir', 
                                                    siteProc = lambda res, ctx, site: len( res[ 'dir' ] ), 
                                                    qProc = lambda res, ctx: sum( res ) )
        statuses[ 'sensors_total' ] = querySites( 'models', 'list_sensors', 
                                                  siteProc = lambda res, ctx, site: len( res ), 
                                                  qProc = lambda res, ctx: sum( res ) )
        return statuses

class Orgs:
    @jsonApi
    def GET( self ):
        return getOrgs()

class GlobalConfigs:
    @jsonApi
    def GET( self ):
        globalConfigs = querySites( 'c2/deploymentmanager', 'get_global_config' )
        return globalConfigs

class FindIp:
    @jsonApi
    def GET( self ):
        params = web.input( ip = None )

        if params.ip is None:
            raise web.HTTPError( '400 Bad Request: ip required' )

        usage = querySites( 'models', 'get_ip_usage', 
                            queryData = { 'ip' : params.ip, 'oid' : getOrgs().keys() },
                            siteProc = lambda res, ctx, site: res[ 'usage' ], 
                            qProc = lambda res, ctx: [ x for x in itertools.chain( res ) ] )
        return usage

# This is a waterhose feed from a single sensor, it streams traffic as json.
class Traffic:
    def GET( self ):
        web.header( 'Content-Type', 'application/json' )
        params = web.input( sid = None )

        sensorInfo = getSiteFor( params.sid )
        if sensorInfo is None:
            raise web.HTTPError( '404 Not Found: sensor not found' )

        sensorInfo, site = sensorInfo

        after = int( time.time() - 5 )
        eventCache = RingCache( maxEntries = 100, isAutoAdd = True )
        
        while True:
            now = int( time.time() )
            newest = 0
            res = querySite( 'models', 'get_timeline', 
                             { 'id' : sensorInfo[ 'id' ],
                               'is_include_content' : True,
                               'after' : after }, defaultSiteProc, site, {} )

            for r in res[ 'events' ]:
                if r[ 2 ] not in eventCache:
                    yield dumpJson( sanitizeJson( r[ 3 ] ) )
                eventTime = int( r[ 0 ] / 1000 )
                if eventTime < now + 30 and eventTime > newest:
                    newest = eventTime

            if 0 != newest:
                after = newest - 1
            gevent.sleep( 2 )

class FindObj:
    @jsonApi
    def GET( self ):
        params = web.input( name = None )

        if params.name is None:
            raise web.HTTPError( '400 Bad Request: name required' )

        objects = querySites( 'models', 'get_obj_list', 
                              queryData = { 'name' : params.name },
                              siteProc = lambda res, ctx, site: dict( [ ( x[ 0 ], ( x[ 1 ], x[ 2 ] ) ) for x in res[ 'objects' ] ] ), 
                              qProc = lambda res, ctx: reduce( lambda x, y: x.update( y ) or x, res, {} ) )
        return objects

class ShowObj:
    @jsonApi
    def GET( self ):
        params = web.input( id = None )

        if params.id is None:
            raise web.HTTPError( '400 Bad Request: id required' )

        objects = querySites( 'models', 'get_obj_view', 
                              queryData = { 'id' : params.id },
                              qProc = lambda res, ctx: mergeObj( res ) )
        return objects

class AtomsFromRoot:
    @jsonApi
    def GET( self ):
        params = web.input( atom = None, max_depth = 5, max_atoms = 1000, with_routing = False )

        if params.atom is None:
            raise web.HTTPError( '400 Bad Request: atom required' )

        atoms = querySites( 'models', 'get_atoms_from_root', 
                              queryData = { 'id' : params.atom, 
                                            'depth' : params.max_depth,
                                            'max_atoms' : params.max_atoms,
                                            'with_routing' : params.with_routing },
                              qProc = lambda res, ctx: firstMatching( res, lambda x: 0 != len( x ) ) )

        return atoms




###############################################################################
# BOILER PLATE
###############################################################################
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser( prog = 'MagicMirror' )
    parser.add_argument( 'port',
                         type = int,
                         help = 'the port to listen on' )
    parser.add_argument( 'configFile',
                         type = str,
                         help = 'the main config file defining LC sites' )
    args = parser.parse_args()

    with open( args.configFile, 'rb' ) as f:
        sites = yaml.load( f.read() )

    urls = ( r'/', 'Index',
             r'/sites', 'Sites',
             r'/status', 'Status',
             r'/orgs', 'Orgs',
             r'/global_configs', 'GlobalConfigs',
             r'/find_ip', 'FindIp',
             r'/traffic', 'Traffic',
             r'/find_obj', 'FindObj',
             r'/show_obj', 'ShowObj',
             r'/atoms_from_root', 'AtomsFromRoot', )
    web.config.debug = False
    app = web.application( urls, globals() )

    os.chdir( g_current_dir )
    app.run()