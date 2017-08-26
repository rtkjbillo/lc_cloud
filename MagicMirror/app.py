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


REST_IDENT = 'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903'
REST_TIMEOUT = 60 * 60
REST_SECRET = None

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
    return json.dumps( data )

def msgpackData( data ):
    web.header( 'Content-Type', 'application/msgpack' )
    return msgpack.packb( data )

###############################################################################
# SITES COMMS
###############################################################################
def defaultSiteProc( result, qContext ):
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
    qData.update( queryData )
    u = urllib2.urlopen( '%s/%s' % (site[ 'url' ], queryCat ), urllib.urlencode( qData ) )
    resp = msgpack.unpackb( u.read() )
    u.close()
    return siteProc( resp, qContext )

def querySites( queryCat, queryAction, queryData = {}, siteProc = defaultSiteProc, qProc = defaultQueryProc ):
    global sites
    p = gevent.pool.Pool()
    ctx = {}

    siteResults = [ x for x in p.imap_unordered( lambda x: querySite( queryCat, queryAction, queryData, siteProc, x, ctx ), sites ) ]
    
    return qProc( siteResults, ctx )


###############################################################################
# PAGES
###############################################################################
class Sites:
    @jsonApi
    def GET( self ):
        global sites
        return sites

class Status:
    @jsonApi
    def GET( self ):
        statuses = querySites( 'c2/deploymentmanager', 'get_global_config' )
        return statuses

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

    urls = ( r'/sites', 'Sites',
             r'/status', 'Status' )
    web.config.debug = False
    app = web.application( urls, globals() )

    os.chdir( g_current_dir )
    app.run()