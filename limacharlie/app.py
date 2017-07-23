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

from gevent import monkey
import gevent
monkey.patch_all()

from beach.beach_api import Beach

import os
import web
from functools import wraps
import uuid
import hashlib
import traceback
import pyqrcode
import base64
import datetime
import json
import re
import time
import urllib
from hcp_helpers import AgentId
from hcp_helpers import _x_
from hcp_helpers import _xm_
from hcp_helpers import normalAtom
from hcp_helpers import InvestigationNature
from hcp_helpers import InvestigationConclusion
from hcp_helpers import HbsCollectorId
from EventInterpreter import EventInterpreter
import markdown
import markdown.extensions.tables

#==============================================================================
#   SITE DEFINITION
#==============================================================================
urls = (
    '/favicon.ico', 'Favicon',
    '/', 'Welcome',
    '/policy', 'Policy',
    '/dashboard', 'Dashboard',
    '/login', 'Login',
    '/logout', 'Logout',
    '/changepassword', 'ChangePassword',
    '/profile', 'Profile',
    '/manage', 'Manage',
    '/installer', 'Installer',
    '/confirm_email', 'ConfirmEmail',
    '/sensors', 'Sensors',
    '/sensor_state', 'SensorState',
    '/sensor_ips', 'SensorIps',
    '/sensor_lastevents', 'SensorLastEvents',
    '/sensor', 'Sensor',
    '/traffic', 'Traffic',
    '/explore', 'Explore',
    '/explorerdata', 'ExplorerData',
    '/event', 'EventView',
    '/search', 'Search',
    '/objsearch', 'ObjSearch',
    '/obj', 'ObjView',
    '/export', 'Exporter',
    '/hostchanges', 'HostChanges',
    '/detects', 'Detects',
    '/capabilities', 'Capabilities',
    '/set_conclusion', 'SetConclusion',
    '/blink', 'Blink',
    '/blink_data', 'BlinkData',
    '/configs', 'Configs',
    '/sensor_configs', 'SensorConfigs',
    '/sensor_bandwidth', 'SensorBandwidth',
    '/sensor_ip_use', 'SensorIpUse',
    '/find_host', 'FindHost',
    '/bulk_search', 'BulkSearch',
    '/obj_instance', 'ObjInstance',
    '/add_tag', 'AddTag',
    '/del_tag', 'DelTag',
    '/del_sensor', 'DelSensor',
)

ADMIN_OID = None
DOMAIN_NAME = None
IS_BACKEND_AVAILABLE = False
IS_OUTAGE_ON = False

ROOT_DIRECTORY = os.path.dirname( os.path.abspath( __file__ ) )
os.chdir( ROOT_DIRECTORY )

web.config.debug = False
web.config.session_parameters['cookie_name'] = 'lc_session'
web.config.session_parameters['cookie_domain'] = None
web.config.session_parameters['timeout'] = 60 * 60 * 24 * 7
web.config.session_parameters['ignore_change_ip'] = True
web.config.session_parameters['secret_key'] = '41a7b8d0-1702-4805-a21c-065067fbf2df'
web.config.session_parameters['expired_message'] = 'Session expired'

app = web.application(urls, globals())
session = web.session.Session( app, 
                               web.session.DiskStore( os.path.join( ROOT_DIRECTORY, 'sessions' ) ), 
                               initializer =  { 'is_logged_in' : False,
                                                'is_admin' : False,
                                                'uid' : None,
                                                'email' : None,
                                                'orgs' : [],
                                                'must_change_password' : False,
                                                'notice' : None,
                                                '_tmp_otp' : None } )

class _renderWrapper( object ):
    def __init__( self, renderer ):
        self._renderer = renderer

    def __getattr__( self, item ):
        res =  getattr( self._renderer, item )
        def _cleanNotice( *args, **kwargs ):
            _res = res( *args, **kwargs )
            session.notice = None
            return _res
        return _cleanNotice

def sanitizeJson( o, summarized = False ):
    if type( o ) is dict:
        for k, v in o.iteritems():
            o[ k ] = sanitizeJson( v, summarized = summarized )
    elif type( o ) is list or type( o ) is tuple:
        o = [ sanitizeJson( x, summarized = summarized ) for x in o ]
    elif type( o ) is uuid.UUID:
        o = str( o )
    else:
        try:
            if ( type(o) is str or type(o) is unicode ) and "\x00" in o: raise Exception()
            json.dumps( o )
        except:
            o = base64.b64encode( o )
        if summarized is not False and len( str( o ) ) > summarized:
            o = str( o[ : summarized ] ) + '...'

    return o

def msTsToTime( ts ):
    return datetime.datetime.fromtimestamp( float( ts ) / 1000 ).strftime( '%Y-%m-%d %H:%M:%S.%f' )[ : -3 ]

def doMarkdown( content ):
    return markdown.markdown( content, extensions = [ 'markdown.extensions.tables' ] )

render = _renderWrapper( web.template.render( 'templates', 
                                              base = 'base', 
                                              globals = { 'session' : session, 
                                                          'str' : str, 
                                                          'msTsToTime' : msTsToTime,
                                                          'AgentId' : AgentId,
                                                          'json' : json,
                                                          'sorted' : sorted,
                                                          'md' : doMarkdown,
                                                          'hash' : lambda x: hashlib.sha256(x).hexdigest(),
                                                          'type' : type },
                                              cache = False ) )
renderAlone = web.template.render( 'templates', globals = { 'session' : session, 
                                                            'str' : str, 
                                                            'msTsToTime' : msTsToTime,
                                                            'AgentId' : AgentId,
                                                            'json' : json,
                                                            'InvestigationNature' : InvestigationNature,
                                                            'InvestigationConclusion' : InvestigationConclusion,
                                                            'sorted' : sorted,
                                                            'md' : doMarkdown,
                                                            'hash' : lambda x: hashlib.sha256(x).hexdigest(),
                                                            'type' : type } )
eventRender = web.template.render( 'templates/custom_events', globals = { 'json' : json,
                                                                          'msTsToTime' : msTsToTime,
                                                                          '_x_' : _x_,
                                                                          '_xm_' : _xm_,
                                                                          'AgentId' : AgentId,
                                                                          'hex' : hex,
                                                                          'sanitize' : sanitizeJson,
                                                                          'EventInterpreter' : EventInterpreter,
                                                                          'sorted' : sorted,
                                                                          'md' : doMarkdown,
                                                                          'hash' : lambda x: hashlib.sha256(x).hexdigest(),
                                                                          'type' : type } )

BEACH_CONFIG_FILE = os.path.join( ROOT_DIRECTORY, 'beach.conf' )
IDENT = 'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903'
beach = Beach( BEACH_CONFIG_FILE, realm = 'hcp' )
model = beach.getActorHandle( 'models', nRetries = 3, timeout = 30, ident = IDENT )
capabilities = beach.getActorHandle( 'analytics/capabilitymanager', nRetries = 3, timeout = 300, ident = IDENT )
sensordir = beach.getActorHandle( 'c2/sensordir', nRetries = 3, timeout = 30, ident = IDENT )
identmanager = beach.getActorHandle( 'c2/identmanager', nRetries = 3, timeout = 30, ident = IDENT )
deployment = beach.getActorHandle( 'c2/deploymentmanager', nRetries = 3, timeout = 30, ident = IDENT )
dataexporter = beach.getActorHandle( 'analytics/dataexporter', nRetries = 1, timeout = 3600, ident = IDENT )
page = beach.getActorHandle( 'paging', nRetries = 3, timeout = 30, ident = IDENT )
audit = beach.getActorHandle( 'c2/audit', nRetries = 3, timeout = 10, ident = IDENT )
reporting = beach.getActorHandle( 'analytics/reporting/', nRetries = 3, timeout = 30, ident = IDENT )
blink = beach.getActorHandle( 'analytics/blinkmodel/', nRetries = 3, timeout = 60, ident = IDENT )
tagging = beach.getActorHandle( 'c2/taggingmanager', nRetries = 3, timeout = 5, ident = IDENT )

print( "Fetching deployment global configurations..." )
_ = deployment.request( 'get_global_config', {} )
print( "configurations retrieved." )
if _.isSuccess:
    ADMIN_OID = uuid.UUID( _.data[ 'global/admin_oid' ] )
    DOMAIN_NAME = _.data[ 'global/uidomain' ]
else:
    raise Exception( 'could not fetch admin oid' )

def pollBackendAvailability( isOneOff = True ):
    global IS_BACKEND_AVAILABLE
    aid = AgentId( '0.0.0.0.0' )
    aid.org_id = ADMIN_OID
    res = model.request( 'list_sensors', { 'aid' : aid }, timeout = 2 )
    res2 = identmanager.request( 'get_org_info', { 'include_all' : True } )
    if res.isSuccess and res2.isSuccess:
        IS_BACKEND_AVAILABLE = True
        print( 'Backend available' )
        if not isOneOff:
            gevent.spawn_later( 10, pollBackendAvailability, isOneOff = False )
    else:
        IS_BACKEND_AVAILABLE = False
        print( 'Backend unavailable' )
        if not isOneOff:
            gevent.spawn_later( 2, pollBackendAvailability, isOneOff = False )

gevent.spawn( pollBackendAvailability, isOneOff = False )

def pollOutageState():
    global IS_OUTAGE_ON
    info = deployment.request( 'get_global_config', {} )
    if info.isSuccess:
        IS_OUTAGE_ON = False if info.data[ 'global/outagestate' ] == '0' else info.data[ 'global/outagetext' ]
    gevent.spawn_later( 30, pollOutageState )
gevent.spawn( pollOutageState )

#==============================================================================
#   HELPERS
#==============================================================================
def redirectTo( page, **kwargs ):
    dest = '/%s?%s' % ( page, urllib.urlencode( kwargs ) )
    raise web.seeother( dest )

def reportError( f ):
    @wraps( f )
    def wrapped( *args, **kwargs ):
        try:
            return f( *args, **kwargs )
        except:
            gevent.spawn( pollBackendAvailability, isOneOff = True )
            return renderAlone.error( traceback.format_exc() )
    return wrapped

def authenticated( f ):
    @wraps( f )
    def wrapped( *args, **kwargs ):
        global IS_BACKEND_AVAILABLE
        global IS_OUTAGE_ON
        if IS_OUTAGE_ON is not False and not session.is_admin:
            return renderAlone.unavailable( IS_OUTAGE_ON )
        if not IS_BACKEND_AVAILABLE:
            return renderAlone.unavailable()
        if session.is_logged_in is not True:
            redirectTo( 'login' )
        elif session.must_change_password is True:
            redirectTo( 'changepassword' )
        else:
            return f( *args, **kwargs )
    return wrapped

def adminAuthenticated( f ):
    @wraps( f )
    def wrapped( *args, **kwargs ):
        if session.is_admin is not True:
            session.notice = 'This page is for administrators only.'
            redirectTo( 'dashboard' )
        else:
            return f( *args, **kwargs )
    return wrapped

class AuthenticatedPage:
    @authenticated
    @reportError
    def GET( self, *args, **kwargs ):
        return self.doGET( *args, **kwargs )

    @authenticated
    @reportError
    def POST( self, *args, **kwargs ):
        return self.doPOST( *args, **kwargs )

class AuthenticatedAdminPage:
    @authenticated
    @adminAuthenticated
    @reportError
    def GET( self, *args, **kwargs ):
        return self.doGET( *args, **kwargs )

    @authenticated
    @reportError
    def POST( self, *args, **kwargs ):
        return self.doPOST( *args, **kwargs )

def jsonApi( f ):
    ''' Decorator to basic exception handling on function. '''
    @wraps( f )
    def wrapped( *args, **kwargs ):
        web.header( 'Content-Type', 'application/json' )
        r = f( *args, **kwargs )
        try:
            return json.dumps( sanitizeJson( r ) )
        except:
            return json.dumps( { 'error' : str( r ),
                                 'exception' : traceback.format_exc() } )
    return wrapped

def wipeSession():
    session.is_logged_in = False
    session.is_admin = False
    session.uid = None
    session.email = None
    session.orgs = []

def refreshOrgMembership():
    info = identmanager.request( 'get_user_membership', { 'uid' : session.uid } )
    if info.isSuccess:
        session.orgs = map( uuid.UUID, info.data[ 'orgs' ] )

def isOrgAllowed( oid ):
    if type( oid ) is not uuid.UUID:
        oid = uuid.UUID( oid )
    if oid in session.orgs:
        return True
    return False

def isSensorAllowed( aid ):
    aid = AgentId( aid )
    info = model.request( 'get_sensor_info', { 'id_or_host' : str( aid ) } )
    if info.isSuccess:
        return isOrgAllowed( AgentId( info.data[ 'id' ] ).org_id )
    return False

def getOrgName( oid ):
    orgs = identmanager.request( 'get_org_info', { 'oid' : oid } )
    res = {}
    if orgs.isSuccess:
        orgs = orgs.data[ 'orgs' ]
        for name, oid, ttls in orgs:
            res[ oid ] = name
    return res

def getOrgNames():
    return getOrgName( session.orgs )

def getUserEmail( uid ):
    uids = identmanager.request( 'get_user_info', { 'uid' : uid } )
    res = {}
    if orgs.isSuccess:
        res = orgs.data
    return res

def getAllSensors( isAllOrgs = False ):
    info = {}
    if not isAllOrgs:
        aid = AgentId( '0.0.0.0.0' )
        for oid in session.orgs:
            aid.org_id = oid
            res = model.request( 'list_sensors', { 'aid' : aid } )
            if res.isSuccess:
                info[ oid ] = res.data
    else:
        res = model.request( 'list_sensors', {} )
        if res.isSuccess:
            for sid, sensor in res.data.iteritems():
                info.setdefault( AgentId( sensor[ 'aid' ] ).org_id, {} )[ sid ] = sensor
    return info

def getHostnames( sid ):
    if type( sid ) not in ( list, tuple ):
        sid = ( sid, )
    hostnames = {}
    for s in sid:
        if s not in hostnames:
            info = model.request( 'get_sensor_info', { 'id_or_host' : s } )
            if info.isSuccess:
                hostnames[ s ] = info.data[ 'hostname' ]
    return hostnames

def setDownloadFileName( name ):
    web.header( 'Content-Disposition', 'attachment;filename="%s"' % name )

def fileDownload( f ):
    ''' Decorator to basic exception handling on function. '''
    @wraps( f )
    def wrapped( *args, **kwargs ):
        web.header( 'Content-Type', 'application/octet-stream' )
        return f( *args, **kwargs )
    return wrapped

#==============================================================================
#   PAGES
#==============================================================================
class Login:
    def GET( self ):
        params = web.input( no2fa = None )
        return renderAlone.login( params.no2fa )

    def POST( self ):
        params = web.input( email = None, password = None, totp = None )

        if params.email is None or params.password is None:
            return renderAlone.error( 'Missing parameter email, password or 2nd factor.' )

        otp = None
        try:
            if params.totp is not None and params.totp != '':
                otp = int( params.totp )
        except:
            return renderAlone.error( 'Invalid 2nd factor format.' )

        info = identmanager.request( 'authenticate', { 'email' : params.email, 'password' : params.password, 'totp' : otp } )
        if not info.isSuccess:
            return renderAlone.error( 'Error authenticating: %s' % info )

        if info.data[ 'is_authenticated' ] is False and info.data.get( 'needs_confirmation', False ) is True:
            return renderAlone.error( 'Account email requires confirmation, please follow the link provided in the invite email.' )            

        if info.data[ 'is_authenticated' ] is True:
            session.is_logged_in = True
            session.uid = uuid.UUID( info.data[ 'uid' ] )
            session.orgs = map( uuid.UUID, info.data[ 'orgs' ] )
            session.email = info.data[ 'email' ]
            session.must_change_password = info.data[ 'must_change_password' ]
            session._tmp_otp = info.data.get( 'otp', None )
            if ADMIN_OID in session.orgs:
                session.is_admin = True
            redirectTo( 'dashboard' )

        return renderAlone.error( 'Invalid email, password or 2nd factor.' )

class Logout:
    def GET( self ):
        wipeSession()
        redirectTo( '' )

    def POST( self ):
        wipeSession()
        redirectTo( '' )

class ConfirmEmail:
    def GET( self ):
        params = web.input( token = None, email = None )

        if params.token is None or params.email is None:
            return renderAlone.error( 'Missing parameter email or token.' )

        info = identmanager.request( 'confirm_email', { 'email' : params.email, 'token' : params.token } )

        if not info.isSuccess:
            return renderAlone.error( 'Error confirming email: %s' % info )

        if info.data[ 'confirmed' ]  is False:
            session.notice = 'Email already confirmed or bad, login as usual.'
            redirectTo( 'login' )

        session.notice = 'Email confirmed, you can now login.'

        redirectTo( 'login', no2fa = 'true' )

class ChangePassword:
    def getOtp( self ):
        totp = session._tmp_otp
        totpImg = None
        if totp is not None:
            totpImg = 'data:image/png;base64,%s' % pyqrcode.create( totp ).png_as_base64_str( scale = 4 )
        return ( totp, totpImg )

    def GET( self ):
        totp, totpImg = self.getOtp()
        return render.changepassword( totp, totpImg )

    def POST( self ):
        params = web.input( password = None, totp = None )
        try:
            if params.totp is not None and params.totp != '':
                totp = int( params.totp )
        except:
            totp = None
        if params.password is None or totp is None:
            session.notice = 'Missing password or 2nd factor.'
            redirectTo( 'changepassword' )
        if session.is_logged_in is not True: return renderAlone.error( 'Must be logged in.' )

        res = identmanager.request( 'change_password', { 'email' : session.email, 'password' : params.password, 'by' : session.email, 'totp' : totp } )
        if not res.isSuccess or not res.data.get( 'is_changed', False ):
            session.notice = 'Error changing password: %s' % res
            totp, totpImg = self.getOtp()
            return render.changepassword( totp, totpImg )

        session.must_change_password = False
        session._tmp_otp = None

        session.notice = 'Password changed successfully.'

        redirectTo( 'policy' )

class Favicon:
    def GET( self ):
        redirectTo( 'static/img/logo.png' )

class Welcome:
    def GET( self ):
        if session.is_logged_in:
            redirectTo( 'dashboard' )
        else:
            return renderAlone.welcome()

class Policy ( AuthenticatedPage ):
    def doGET( self ):
        policy = ''
        info = deployment.request( 'get_global_config', {} )
        if info.isSuccess:
            policy = info.data[ 'global/policy' ]
        return render.policy( policy )

class Dashboard ( AuthenticatedPage ):
    def doGET( self ):
        cards = []
        orgNames = getOrgNames()
        orgSensors = getAllSensors()
        allLiveDir = sensordir.request( 'get_dir', {} )
        if allLiveDir.isSuccess:
            allLiveDir = allLiveDir.data[ 'dir' ]
        else:
            allLiveDir = {}
        if session.is_admin:
            mergedSensors = {}
            for oid, sensors in getAllSensors( isAllOrgs = True ).iteritems():
                for sid, sensor in sensors.iteritems():
                    sensor[ 'realtime' ] = True if str( AgentId( sensor[ 'aid' ] ).sensor_id ) in allLiveDir else False
                    mergedSensors[ sid ] = sensor
                if oid not in session.orgs:
                    cards.append( card_sensor_stats( str( oid ), sensors, str( oid ) ) )
            cards.insert( 0, card_sensor_stats( 'Total', mergedSensors, 'total' ) )
            del( mergedSensors )
        welcomeMessage = ''
        info = deployment.request( 'get_global_config' )
        if info.isSuccess:
            welcomeMessage = info.data[ 'global/whatsnew' ]
        for oid, sensors in orgSensors.iteritems():
            for sid, sensor in sensors.iteritems():
                sensor[ 'realtime' ] = True if str( AgentId( sensor[ 'aid' ] ).sensor_id ) in allLiveDir else False
            cards.insert( 1, card_sensor_stats( orgNames[ str( oid ) ], sensors, str( oid ) ) )
        return render.dashboard( cards, welcomeMessage )

class Profile ( AuthenticatedPage ):
    def renderProfile( self ):
        orgs = identmanager.request( 'get_org_info', { 'oid' : session.orgs } )
        if orgs.isSuccess:
            orgs = orgs.data[ 'orgs' ]
        else:
            return renderAlone.error( 'Error fetching orgs: %s.' % str( orgs ) )
        if session.is_admin:
            all_orgs = identmanager.request( 'get_org_info', { 'include_all' : True } )
            if all_orgs.isSuccess:
                all_orgs = all_orgs.data[ 'orgs' ]
            else:
                return renderAlone.error( 'Error fetching all orgs: %s.' % str( orgs ) )
            all_users = identmanager.request( 'get_user_info', { 'include_all' : True } )
            if all_users.isSuccess:
                all_users = all_users.data
            else:
                return renderAlone.error( 'Error fetching all users: %s.' % str( orgs ) )
        else:
            all_orgs = None
            all_users = None
        extra_cards = []
        org_configs = {}
        for org in orgs:
            confInfo = deployment.request( 'get_org_config', { 'oid' : org[ 1 ] } )
            if confInfo.isSuccess:
                org_configs[ ( org[ 0 ], org[ 1 ] ) ] = confInfo.data
            extra_cards.append( card_org_membership( org[ 0 ], org[ 1 ] ) )
            extra_cards.append( card_org_retention( org[ 0 ], org[ 1 ], org[ 2 ] ) )
        return render.profile( orgs, all_orgs, extra_cards, all_users, org_configs )

    def doGET( self ):
        return self.renderProfile()

    def doPOST( self ):
        params = web.input( action = None, 
                            orgs = [], 
                            email = None, 
                            with_key = False, with_profile = False, 
                            oid = None, 
                            slacktoken = None, slackbottoken = None,
                            webhook_secret = None, webhook_dest = None )
        if params.action is None:
            session.notice = 'Missing action parameter.'
            redirectTo( 'profile' )

        if not session.is_admin:
            if any( map( lambda x: not self.isOrgAllowed( x ), params.orgs ) ):
                session.notice = 'Permission denied on %s' % oid
                redirectTo( 'profile' )

        if 'admin_join' == params.action:
            for oid in params.orgs:
                res = identmanager.request( 'add_user_to_org', { 'email' : session.email, 'oid' : oid, 'by' : session.email } )
                if not res.isSuccess or not res.data.get( 'is_added', False ): 
                    session.notice = 'Error adding user %s to %s by %s (%s).' % ( session.email, oid, session.email, str( res ) )
                    redirectTo( 'profile' )
                audit.shoot( 'record', { 'oid' : ADMIN_OID, 'etype' : 'admin_join_org', 'msg' : 'Admin %s admin-joined oid %s.' % ( session.email, oid ) } )
            session.notice = 'Success joining %s' % oid
        elif 'join' == params.action:
            if params.email is None:
                session.notice = 'Missing user email parameter.'
                redirectTo( 'profile' )
            for oid in params.orgs:
                res = identmanager.request( 'add_user_to_org', { 'email' : params.email, 'oid' : oid, 'by' : session.email } )
                if not res.isSuccess or not res.data.get( 'is_added', False ):
                    session.notice = 'Error adding user %s to %s by %s (%s).' % ( params.email, oid, session.email, str( res ) )
                    redirectTo( 'profile' )
            session.notice = 'Success adding %s to orgs' % params.email
        elif 'leave' == params.action:
            for oid in params.orgs:
                res = identmanager.request( 'remove_user_from_org', { 'email' : session.email, 'oid' : oid, 'by' : session.email } )
                if not res.isSuccess or not res.data.get( 'is_removed', False ):
                    session.notice = 'Error removing user %s from %s by %s (%s).' % ( session.email, oid, session.email, str( res ) )
                    redirectTo( 'profile' )
            session.notice = 'Success leaving orgs'
        elif 'kick' == params.action:
            if params.email is None: 
                session.notice = 'Missing user email parameter.'
                redirectTo( 'profile' )
            for oid in params.orgs:
                res = identmanager.request( 'remove_user_from_org', { 'email' : params.email, 'oid' : oid, 'by' : session.email } )
                if not res.isSuccess or not res.data.get( 'is_removed', False ): 
                    session.notice = 'Error removing user %s from %s by %s (%s).' % ( params.email, oid, session.email, str( res ) )
                    redirectTo( 'profile' )
            session.notice = 'Success removing %s from orgs' % params.email
        elif 'account_create' == params.action and session.is_admin:
            tempPassword = str( uuid.uuid4() )
            res = identmanager.request( 'create_user', { 'email' : params.email, 'by' : session.email, 'password' : tempPassword } )
            if res.isSuccess and res.data[ 'is_created' ] is True:
                confirmToken = res.data[ 'confirmation_token' ]
                res = page.request( 'page', { 'to' : params.email, 
                                              'msg' : '\n'.join( [ 'Your new %s account has been created.' % DOMAIN_NAME,
                                                                   '',
                                                                   'You can now login at %s with the temporary password: %s' % ( DOMAIN_NAME, tempPassword ),
                                                                   '',
                                                                   'Confirm your email address by following this link: <a href="%s/confirm_email?token=%s&email=%s">%s/confirm_email?token=%s&email=%s</a>' % ( DOMAIN_NAME, confirmToken, params.email, DOMAIN_NAME, confirmToken, params.email ),
                                                                   '',
                                                                   'Get help and stay up to date the following ways:',
                                                                   ' - Twitter: @rp_limacharlie',
                                                                   ' - Google Groups: <a href="https://groups.google.com/d/forum/limacharlie">https://groups.google.com/d/forum/limacharlie</a>',
                                                                   ' - Slack Channel: <a href="http://limacharlie.herokuapp.com/">http://limacharlie.herokuapp.com/</a>',
                                                                   ' - Wiki: <a href="https://github.com/refractionPOINT/limacharlie/wiki">https://github.com/refractionPOINT/limacharlie/wiki</a>',
                                                                   ' - YouTube Tutorials: <a href="https://www.youtube.com/channel/UCR0GhNmc4gVcD9Uj07HS5AA">https://www.youtube.com/channel/UCR0GhNmc4gVcD9Uj07HS5AA</a>',
                                                                   '',
                                                                   '',
                                                                   'The %s team.' % DOMAIN_NAME ] ), 
                                              'subject' : '%s Account Created' % DOMAIN_NAME } )
                if not res.isSuccess:
                    link = 'http://%s/confirm_email?token=%s&email=%s' % ( DOMAIN_NAME, confirmToken, params.email )
                    return renderAlone.error( 'Failed to send automated email, is your paging email account configured? User is created, copy this confirmation link (that could not be email), the user MUST use this link to login for the first time: %s<br/><br/>The temporary password for the account is %s' % ( link, tempPassword ) )
                session.notice = 'Success creating user %s' % params.email
            else:
                session.notice = 'Error creating users: %s' % res
                redirectTo( 'profile' )
        elif 'account_delete' == params.action and session.is_admin:
            res = identmanager.request( 'delete_user', { 'email' : params.email, 'by' : session.email } )
            if not res.isSuccess or not res.data.get( 'is_deleted', False ):
                session.notice = 'Error deleting user: %s' % res
                redirectTo( 'profile' )
            session.notice = 'Success deleting account %s' % params.email
        elif 'org_create' == params.action and session.is_admin:
            tempPassword = str( uuid.uuid4() )
            res = identmanager.request( 'create_org', { 'name' : params.orgname, 'by' : session.email } )
            if not res.isSuccess or res.data[ 'is_created' ] is not True:
                session.notice = 'Error creating org.'
                redirectTo( 'profile' )
            else:
                oid = res.data[ 'oid' ]
                res = deployment.request( 'deploy_org', { 'oid' : oid } )
                if res.isSuccess:
                    session.notice = 'Org created with oid: %s' % oid
                else:
                    identmanager.request( 'remove_org', { 'by' : session.email, 'oid' : oid } )
                    session.notice = 'Error deploying org: %s' % res
        elif 'org_deploy' == params.action:
            for oid in params.orgs:
                withKey = True if params.with_key is not False else False
                withProfile = True if params.with_profile is not False else False
                res = deployment.request( 'deploy_org', { 'is_generate_key' : withKey, 'oid' : oid, 'skip_profiles' : not withProfile } )
                notice = []
                if not res.isSuccess: 
                    notice.append( 'Error generating sensors for %s.' % ( oid, ) )
                else:
                    audit.shoot( 'record', { 'oid' : ADMIN_OID, 'etype' : 'org_deploy', 'msg' : 'Admin %s re-generated sensors for %s.' % ( session.email, oid ) } )
                    audit.shoot( 'record', { 'oid' : oid, 'etype' : 'org_deploy', 'msg' : 'Admin %s re-generated sensors for %s.' % ( session.email, oid ) } )

                if 0 != len( notice ):
                    session.notice = '\n'.join( notice )
                    redirectTo( 'profile' )
            session.notice = 'Success generating sensors.'
        elif 'slack_update' == params.action:
            if not isOrgAllowed( uuid.UUID( params.oid ) ):
                session.notice = 'Permission denied on %s' % oid
                redirectTo( 'profile' )
            res = deployment.request( 'set_config', { 'conf' : '%s/slack_token' % params.oid, 'value' : params.slacktoken, 'by' : session.email } )
            if not res.isSuccess: 
                session.notice = 'Error setting Slack token for %s: %s.' % ( params.oid, str( res ) )
                redirectTo( 'profile' )
            res = deployment.request( 'set_config', { 'conf' : '%s/slack_bot_token' % params.oid, 'value' : params.slackbottoken, 'by' : session.email } )
            if not res.isSuccess: 
                session.notice = 'Error setting Slack bot token for %s: %s.' % ( params.oid, str( res ) )
                redirectTo( 'profile' )
            session.notice = 'Success setting Slack token for: %s' % params.oid
        elif 'webhook_update' == params.action:
            if not isOrgAllowed( uuid.UUID( params.oid ) ):
                session.notice = 'Permission denied on %s' % oid
                redirectTo( 'profile' )
            res = deployment.request( 'set_config', { 'conf' : '%s/webhook_secret' % params.oid, 'value' : params.webhook_secret, 'by' : session.email } )
            if not res.isSuccess: 
                session.notice = 'Error setting webhook secret for %s: %s.' % ( params.oid, str( res ) )
                redirectTo( 'profile' )
            res = deployment.request( 'set_config', { 'conf' : '%s/webhook_dest' % params.oid, 'value' : params.webhook_dest, 'by' : session.email } )
            if not res.isSuccess: 
                session.notice = 'Error setting webhook dest for %s: %s.' % ( params.oid, str( res ) )
                redirectTo( 'profile' )
            session.notice = 'Success setting webhook for: %s' % params.oid
        else:
            session.notice = 'Action not supported.'
            redirectTo( 'profile' )

        refreshOrgMembership()

        redirectTo( 'profile' )

class Manage ( AuthenticatedPage ):
    def doGET( self ):
        params = web.input()

        info = model.request( 'get_backend_config', { 'oid' : session.orgs } )
        if not info.isSuccess:
            return renderAlone.error( 'Error getting backend configs: %s' % info )

        installers = info.data[ 'hcp_installers' ]
        profiles = info.data[ 'hbs_profiles' ]

        info = audit.request( 'get_log', { 'oid' : session.orgs, 'limit' : 20 } )
        if not info.isSuccess:
            return renderAlone.error( 'Error getting audit logs: %s' % info )

        logs = info.data[ 'logs' ]

        return render.manage( installers, profiles, getOrgNames(), logs )

class Installer ( AuthenticatedPage ):
    @fileDownload
    def doGET( self ):
        params = web.input( oid = None, iid = None, hash = None )

        oid = None
        iid = None
        hash = None
        try:
            oid = uuid.UUID( params.oid )
            iid = uuid.UUID( params.iid )
            hash = params.hash
        except:
            session.notice = 'Error: bad or missing parameter.'
            redirectTo( 'manage' )

        if not isOrgAllowed( oid ):
            session.notice = 'Permission denied.'
            redirectTo( 'manage' )

        res = model.request( 'get_installer', { 'oid' : oid, 'iid' : iid, 'hash' : hash, 'with_content' : True } )

        if not res.isSuccess or 0 == len( res.data[ 'installers' ] ):
            session.notice = 'Error getting installer: %s' % res
            redirectTo( 'manage' )

        setDownloadFileName( re.sub( '_........\-....\-....\-....\-............', '', res.data[ 'installers' ][ 0 ][ 'description' ] ) )

        return res.data[ 'installers' ][ 0 ][ 'data' ]

class Sensors ( AuthenticatedPage ):
    def doGET( self ):
        cards = []
        orgNames = getOrgNames()
        orgSensors = getAllSensors()
        for oid, sensors in orgSensors.iteritems():
            cards.append( card_sensors( orgNames[ str( oid ) ], sensors ) )
        return render.sensors( cards )

class SensorState ( AuthenticatedPage ):
    @jsonApi
    def doGET( self ):
        params = web.input( sensor_id = None )

        if params.sensor_id is None:
            raise web.HTTPError( '400 Bad Request: sensor id required' )

        info = model.request( 'get_sensor_info', { 'id_or_host' : params.sensor_id } )

        if not isOrgAllowed( AgentId( info.data[ 'id' ] ).org_id ):
            raise web.HTTPError( '401 Unauthorized' )
        live_status = sensordir.request( 'get_endpoint', { 'aid' : params.sensor_id } )
        if not live_status.isSuccess:
            live_status = False
            transfered = 0
        else:
            transfered = live_status.data.get( 'transfered', 0 )
            live_status = True if live_status.data.get( 'endpoint', None ) is not None else False

        if not info.isSuccess:
            raise web.HTTPError( '503 Service Unavailable: %s' % str( info ) )

        if 0 == len( info.data ):
            raise web.HTTPError( '204 No Content: sensor not found' )

        info.data[ 'live_status' ] = live_status
        info.data[ 'transfered' ] = transfered

        return info.data

class SensorIps ( AuthenticatedPage ):
    @jsonApi
    def doGET( self ):
        params = web.input( sensor_id = None )

        if params.sensor_id is None:
            raise web.HTTPError( '400 Bad Request: sensor id required' )

        info = model.request( 'get_sensor_info', { 'id_or_host' : params.sensor_id } )

        if not isOrgAllowed( AgentId( info.data[ 'id' ] ).org_id ):
            raise web.HTTPError( '401 Unauthorized' )
        
        info = model.request( 'get_lastips', { 'id' : params.sensor_id } )

        if not info.isSuccess:
            raise web.HTTPError( '503 Service Unavailable: %s' % str( info ) )

        return info.data

class SensorLastEvents ( AuthenticatedPage ):
    @jsonApi
    def doGET( self ):
        params = web.input( sensor_id = None )

        if params.sensor_id is None:
            raise web.HTTPError( '400 Bad Request: sensor id required' )

        info = model.request( 'get_sensor_info', { 'id_or_host' : params.sensor_id } )

        if not isOrgAllowed( AgentId( info.data[ 'id' ] ).org_id ):
            raise web.HTTPError( '401 Unauthorized' )
        
        info = model.request( 'get_lastevents', { 'id' : params.sensor_id } )

        if not info.isSuccess:
            raise web.HTTPError( '503 Service Unavailable: %s' % str( info ) )

        return info.data

class Sensor ( AuthenticatedPage ):
    def doGET( self ):
        params = web.input( sid = None )

        if params.sid is None:
            return renderAlone.error( 'Must provide a sid.' )

        info = model.request( 'get_sensor_info', { 'id_or_host' : params.sid } )
        aid = AgentId( info.data[ 'id' ] )
        hostname = info.data[ 'hostname' ]
        if not isOrgAllowed( aid.org_id ):
            return renderAlone.error( 'Unauthorized.' )

        cards = []
        orgNames = getOrgNames()
        tags = []
        resp = tagging.request( 'get_tags', { 'sid' : aid.sensor_id } )
        if resp.isSuccess:
            tags = resp.data.get( 'tags', {} ).values()[ 0 ].keys()
        cards.append( card_sensor_ident( aid, hostname, orgNames[ str( aid.org_id ) ], tags ) )
        cards.append( card_sensor_last( aid, hostname ) )
        cards.append( card_sensor_changes( aid, hostname ) )
        cards.append( card_sensor_bandwidth( aid, hostname ) )
        cards.append( card_sensor_traffic( aid, hostname, None, None ) )
        return render.sensor( hostname, aid, cards )

class Traffic ( AuthenticatedPage ):
    @jsonApi
    def GET( self ):
        params = web.input( sid = None, after = None, before = None, max_size = '4096', rich = 'false', max_time = None )

        if params.sid is None:
            raise web.HTTPError( '400 Bad Request: sid required' )

        if params.after is None or '' == params.after:
            raise web.HTTPError( '400 Bad Request: need start time' )

        start_time = int( params.after )
        max_size = int( params.max_size )
        max_time = 60 * 60 * 4
        if params.max_time is not None and '' != params.max_time:
            max_time = int( params.max_time )
        end_time = None
        if params.before is not None and '' != params.before and '0' != params.before:
            end_time = int( params.before )
        rich = True if params.rich == 'true' else False

        if 0 != start_time:
            effective_end_time = int( time.time() )
            if end_time is not None:
                effective_end_time = end_time
            if max_time < ( effective_end_time - start_time ):
                raise web.HTTPError( '400 Bad Request: maximum time lapse: %d - %d > %d' % ( effective_end_time, start_time, max_time ) )

        if 0 == start_time:
            start_time = int( time.time() ) - 5

        req = { 'id' : params.sid,
                'is_include_content' : True,
                'after' : start_time }

        if not rich:
            req[ 'max_size' ] = max_size

        if end_time is not None:
            req[ 'before' ] = end_time

        info = model.request( 'get_timeline', req )

        if not info.isSuccess:
            return renderAlone.error( str( info ) )

        if 0 == int( params.after ):
            info.data[ 'new_start' ] = start_time

        if rich:
            originalEvents = info.data.get( 'events', [] )
            info.data[ 'events' ] = []
            for event in originalEvents:
                if event[ 3 ] is None: continue
                thisAtom = event[ 3 ].values()[ 0 ].get( 'hbs.THIS_ATOM', None )
                richEvent = None
                if hasattr( eventRender, event[ 1 ] ):
                    try:
                        richEvent = str( getattr( eventRender, event[ 1 ] )( sanitizeJson( event[ 3 ] ) ) )
                    except:
                        richEvent = None
                if richEvent is None:
                    richEvent = str( eventRender.default( sanitizeJson( event[ 3 ], summarized = 1024 ) ) )

                info.data[ 'events' ].append( ( event[ 0 ],
                                                event[ 1 ],
                                                event[ 2 ],
                                                richEvent,
                                                thisAtom ) )
        return info.data

class Explore ( AuthenticatedPage ):
    def doGET( self ):
        params = web.input( atid = None )

        atid = params.atid

        try:
            atid = uuid.UUID( atid )
        except:
            atid = None

        if atid is None:
            return renderAlone.error( 'Must provide a valid atid.' )

        cards = []
        cards.append( card_event_explorer( atid ) )
        return render.explore( cards )

class ExplorerData ( AuthenticatedPage ):
    @jsonApi
    def doGET( self ):
        params = web.input( atid = None )

        if params.atid is None:
            raise web.HTTPError( '400 Bad Request: atid required' )

        effectiveId = normalAtom( params.atid )

        info = model.request( 'get_atoms_from_root', { 'id' : effectiveId, 'with_routing' : True } )

        if not info.isSuccess:
            raise web.HTTPError( '503 Service Unavailable : %s' % str( info ) )

        info.data = list( info.data )

        for routing, _ in info.data:
            if not isOrgAllowed( AgentId( routing[ 'aid' ] ).org_id ):
                raise web.HTTPError( '401 Unauthorized' )

        # Make sure the root is present
        isFound = False
        for _, atom in info.data:
            if effectiveId == normalAtom( atom.values()[0]['hbs.THIS_ATOM'] ):
                isFound = True
                break
        info.data = map( lambda x: { 'data' : x[ 1 ], 'key' : EventInterpreter( x[ 1 ] ).shortKey() }, info.data )
        if not isFound:
            info.data.append( { 'data' : { 'UNKNOWN' : { 'hbs.THIS_ATOM' : effectiveId } },
                                'key' : 'UNKNOWN' } )

        # Summarize the events

        return info.data

class EventView ( AuthenticatedPage ):
    def doGET( self ):
        params = web.input( eid = None, summarized = 1024 )

        if params.eid is None:
            return renderAlone.error( 'need to supply an event eid' )

        info = model.request( 'get_event', { 'id' : params.eid, 'with_routing' : True } )

        if not info.isSuccess:
            return renderAlone.error( str( info ) )

        event = info.data.get( 'event', [ None, ( {}, {} ) ] )
        eid, event = event
        routing, event = event

        if not isOrgAllowed( AgentId( routing[ 'aid' ] ).org_id ):
            return renderAlone.error( 'Unauthorized.' )

        thisAtom = event.values()[ 0 ].get( 'hbs.THIS_ATOM', None )

        cards = []
        cards.append( card_event( ( eid, sanitizeJson( event, summarized = params.summarized ) ), thisAtom ) )

        return render.event( cards )

class Search ( AuthenticatedPage ):
    def doGET( self ):
        params = web.input( term = None )

        if params.term is None:
            return renderAlone.error( 'need to supply search term' )

        info = model.request( 'get_sensor_info', { 'id_or_host' : params.term } )
        if info.isSuccess and 'id' in info.data:
            redirectTo( 'sensor', sid = AgentId( info.data[ 'id' ] ).sensor_id )

        info = model.request( 'get_obj_list', { 'name' : params.term } )
        redirectTo( 'objsearch', obj = params.term )

class ObjSearch ( AuthenticatedPage ):
    def doGET( self ):
        return self.doSearch()

    def doPOST( self ):
        return self.doSearch()

    def doSearch( self ):
        params = web.input( obj = None )

        if params.obj is None:
            return renderAlone.error( 'need to supply an obj' )

        objNames = map( lambda x: x.strip(), params.obj.split( '\n' ) )
        results = {}
        for objName in objNames:
            info = model.request( 'get_obj_list', { 'name' : objName, 'orgs' : session.orgs } )
            if info.isSuccess and 0 != len( info.data[ 'objects' ] ):
                for oid, oname, otype in info.data[ 'objects' ]:
                    results[ oid ] = { 'name' : oname, 'type' : otype, 'locs' : 0, 'glocs' : 0 }

        if 0 != len( results ):
            info = model.request( 'get_obj_loc', { 'objects' : [ ( x[ 1 ][ 'name' ], x[ 1 ][ 'type' ] ) for x in results.iteritems() ] } )
            if info.isSuccess:
                for oid, sid, ts in info.data:
                    results[ oid ][ 'glocs' ] += 1
                    if isSensorAllowed( sid ):
                        results[ oid ][ 'locs' ] += 1

        tagInfo = {}
        hostnames = {}
        resp = tagging.request( 'search_tags', { 'tag' : params.obj, 'oid' : session.orgs } )
        if resp.isSuccess:
            resp = tagging.request( 'get_tags', { 'sid' : resp.data.get( 'hosts', [] ) } )
            if resp.isSuccess:
                tagInfo = resp.data.get( 'tags', {} )
                hostnames = getHostnames( tagInfo.keys() )

        return render.objsearch( results, tagInfo, hostnames )

class BulkSearch ( AuthenticatedPage ):
    def doGET( self ):
        return render.bulk_search()

class ObjView ( AuthenticatedPage ):
    def doGET( self ):
        params = web.input( oid = None, sid = None )

        if params.oid is None:
            return renderAlone.error( 'need to supply an oid' )

        filt = { 'id' : params.oid, 'orgs' : session.orgs }
        if params.sid is not None:
            if '' == params.sid or 'None' == params.sid or 'null' == params.sid:
                params.sid = None
            else:
                params.sid = uuid.UUID( params.sid )
                filt[ 'host' ] = params.sid
        if params.sid is not None:
            info = model.request( 'get_sensor_info', { 'id_or_host' : params.sid } )

            if not isOrgAllowed( AgentId( info.data[ 'id' ] ).org_id ):
                return renderAlone.error( 'Unauthorized.' )
        info = model.request( 'get_obj_view', filt )
        cards = []
        if info.isSuccess and 0 != len( info.data ):
            hostnames = getHostnames( [ x[ 0 ] for x in info.data[ 'olocs' ] ] )

            cards.append( card_object( info.data[ 'id' ], 
                                       info.data[ 'oname' ],
                                       info.data[ 'otype' ],
                                       info.data[ 'olocs' ],
                                       info.data[ 'locs' ],
                                       info.data[ 'rlocs' ],
                                       info.data[ 'parents' ],
                                       info.data[ 'children' ],
                                       params.sid,
                                       hostnames ) )
        elif 0 == len( info.data ):
            session.notice = 'No object found.'
        else:
            session.notice = 'Error fetching object info: %s' % str( info )
        
        return render.object( info.data[ 'id' ], info.data[ 'oname' ], info.data[ 'otype' ], cards )

class Exporter ( AuthenticatedPage ):
    @fileDownload
    def doGET( self ):
        params = web.input( sid = None, after = None, before = None, is_json = True, is_flat = False )

        if params.sid is None:
            return renderAlone.error( 'Must provide a sid.' )

        info = model.request( 'get_sensor_info', { 'id_or_host' : params.sid } )
        aid = AgentId( info.data[ 'id' ] )
        if not isOrgAllowed( aid.org_id ):
            raise web.HTTPError( '401 Unauthorized' )

        req = { 'sid' : params.sid,
                'is_json' : params.is_json,
                'is_flat' : params.is_flat,
                'oid' : aid.org_id, 'by' : session.email }
        if params.after is not None and '0' != params.after:
            req[ 'after' ] = int( params.after )
        if params.before is not None and '0' != params.before:
            req[ 'before' ] = int( params.before )

        res = dataexporter.request( 'export_sensor', req )

        if not res.isSuccess:
            raise web.HTTPError( '503 Service Unavailable: %s' % str( res ) )

        setDownloadFileName( res.data[ 'export_name' ] )

        return res.data[ 'export' ]

class HostChanges ( AuthenticatedPage ):
    @jsonApi
    def doGET( self ):
        params = web.input( sensor_id = None )

        if params.sensor_id is None:
            raise web.HTTPError( '400 Bad Request: sensor id required' )

        info = model.request( 'get_sensor_info', { 'id_or_host' : params.sensor_id } )

        if not isOrgAllowed( AgentId( info.data[ 'id' ] ).org_id ):
            raise web.HTTPError( '401 Unauthorized' )

        changes = model.request( 'get_host_changes', { 'id' : params.sensor_id } )
        if not changes.isSuccess:
            raise web.HTTPError( '503 Service Unavailable: %s' % str( changes ) )

        return changes.data

class Detects ( AuthenticatedPage ):
    def doGET( self ):
        params = web.input( before = None, after = None, is_all = False )

        before = int( params.before ) if params.before is not None else None
        after = int( params.after ) if params.after is not None else None
        if after is None and before is None:
            after = int( time.time() ) - ( 60 * 60 * 24 * 7 )

        allDetects = []
        for oid in session.orgs:
            detects = model.request( 'get_detects', { 'oid' : oid, 
                                                      'before' : before, 
                                                      'after' : after } )
            if detects.isSuccess:
                allDetects.extend( detects.data[ 'reports' ] )

        allDetects = sorted( allDetects, key = lambda d: d[ 0 ], reverse = True )
        
        cards = []
        hostcache = {}
        orgNames = getOrgNames()
        for detect in allDetects:
            sensors = [ x for x in detect[ 2 ].split( ' / ' ) ]
            hostcache.update( getHostnames( sensors ) )
            info = model.request( 'get_detect', { 'id' : detect[ 1 ], 'with_inv' : True } )
            investigations = []
            if info.isSuccess:
                investigations = info.data[ 'inv' ]
            cards.append( renderAlone.card_detect( detect, hostcache, orgNames, investigations ) )

        return render.detects( cards )

class Capabilities ( AuthenticatedPage ):
    def doPOST( self ):
        if session.is_admin is not True:
            session.notice = 'Error: capabilities modifications is limited to administrators.'
            redirectTo( 'dashboard' )

        params = web.input( urlToAdd = None, nameToRem = None, nameToAdd = None, argsToAdd = None, contentToAdd = None )

        cap = {}

        resp = None
        if ( ( ( params.urlToAdd is not None and params.urlToAdd != '' ) or 
               ( params.contentToAdd is not None and params.contentToAdd != '' ) ) and ( params.nameToAdd is not None
                                                                                         and params.nameToAdd != '' ) ):
            req = { 'user_defined_name' : params.nameToAdd,
                    'args' : params.argsToAdd }
            if params.urlToAdd is not None and params.urlToAdd != '':
                req[ 'url' ] = params.urlToAdd
            else:
                req[ 'content' ] = params.contentToAdd
            resp = capabilities.request( 'load', req )
        elif params.nameToRem is not None and params.nameToRem != '':
            resp = capabilities.request( 'unload', { 'user_defined_name' : params.nameToRem } )

        if resp is None:
            session.notice = 'Error: missing parameters'
        elif not resp.isSuccess:
            session.notice = 'Error: %s' % resp

        redirectTo( 'capabilities' )

    def doGET( self ):
        params = web.input()

        cap = {}

        capReq = capabilities.request( 'list', {} )
        if capReq.isSuccess:
            cap.update( capReq.data[ 'loadedDetections' ] )
            cap.update( capReq.data[ 'loadedPatrols' ] )

        return render.capabilities( capabilities = cap, is_admin = session.is_admin )

class SetConclusion ( AuthenticatedPage ):
    def doGET( self ):
        params = web.input( did = None, hunter = None, nature = None, conclusion = None )

        if params.did is None:
            return renderAlone.error( 'need to supply a did' )

        if params.hunter is None:
            return renderAlone.error( 'need to supply a hunter' )

        try:
            params.nature = int( params.nature )
        except:
            params.nature = None

        try:
            params.conclusion = int( params.conclusion )
        except:
            params.conclusion = None

        if params.nature is None and params.conclusion is None:
            return renderAlone.error( 'need to supply a nature or conclusion' )

        resp = model.request( 'get_detect', { 'id' : params.did, 
                                              'with_events' : False,
                                              'with_inv' : False } )
        if not resp.isSuccess:
            session.notice = 'Error: could not find investigation.'
            redirectTo( 'detects' )

        isAllowed = False
        try:
            if isOrgAllowed( AgentId( resp.data[ 'detect' ][ 2 ].split( ' / ' )[ 0 ] ).org_id ):
                isAllowed = True
        except:
            isAllowed = False

        if not isAllowed:
            return renderAlone.error( 'Unauthorized.' )

        if params.nature is not None:
            resp = reporting.request( 'set_inv_nature', { 'inv_id' : params.did, 
                                                          'hunter' : params.hunter, 
                                                          'nature' : params.nature } )

        if not resp.isSuccess:
            session.notice = 'Error: %s' % resp
            redirectTo( 'detects' )

        if params.conclusion is not None:
            resp = reporting.request( 'set_inv_conclusion', { 'inv_id' : params.did, 
                                                              'hunter' : params.hunter, 
                                                              'conclusion' : params.conclusion } )

        if not resp.isSuccess:
            session.notice = 'Error: %s' % resp
            redirectTo( 'detects' )

        session.notice = 'Investigation conclusion set.'

        redirectTo( 'detects' )


class Blink ( AuthenticatedPage ):
    def doGET( self ):
        params = web.input( sid = None, after = None, before = None )

        if params.sid is None:
            return renderAlone.error( 'Must provide a sid.' )

        if params.after is None or params.after == '':
            params.after = time.time() - ( 60 * 10 * 1 )
        params.after = int( params.after )

        if params.before is None or params.before == '':
            params.before = time.time() + ( 60 * 60 * 1 )
        params.before = int( params.before )

        info = model.request( 'get_sensor_info', { 'id_or_host' : params.sid } )
        aid = AgentId( info.data[ 'id' ] )
        hostname = info.data[ 'hostname' ]
        if not isOrgAllowed( aid.org_id ):
            return renderAlone.error( 'Unauthorized.' )

        card = renderAlone.card_blink( aid.sensor_id, hostname, params.after, params.before )

        return render.blink( hostname, card )

class BlinkData ( AuthenticatedPage ):
    @jsonApi
    def doGET( self ):
        params = web.input( sid = None, before = None, after = None )

        if params.sid is None:
            raise web.HTTPError( '400 Bad Request: sid required' )

        if params.after is None:
            raise web.HTTPError( '400 Bad Request: after required' )

        if params.before is None:
            raise web.HTTPError( '400 Bad Request: before required' )

        params.after = int( params.after )
        params.before = int( params.before )

        info = model.request( 'get_sensor_info', { 'id_or_host' : params.sid } )

        aid = AgentId( info.data[ 'id' ] )
        if not isOrgAllowed( aid.org_id ):
            raise web.HTTPError( '401 Unauthorized' )
        
        info = blink.request( 'get_host_blink', { 'aid' : aid, 'after' : params.after, 'before' : params.before } )

        if not info.isSuccess:
            raise web.HTTPError( '503 Service Unavailable: %s' % str( info ) )

        return info.data

class Configs ( AuthenticatedAdminPage ):
    def doGET( self ):
        params = web.input()

        info = deployment.request( 'get_global_config', {} )
        if info.isSuccess:
            info = info.data
        else:
            return renderAlone.error( 'Could not global settings from deployment manager: %s' % str( info ) )

        return render.configs( info )

    def doPOST( self ):
        global DOMAIN_NAME
        params = web.input( primary_domain = None, primary_port = None,
                            secondary_domain = None, secondary_port = None,
                            enrollmentsecret = None, 
                            paging_user = None, paging_from = None, paging_password = None,
                            virustotalkey = None, 
                            sensorpackage = None,
                            uidomain = None,
                            whatsnew = None,
                            outagetext = None,
                            outagestate = None,
                            policy = None )

        if params.primary_domain is not None and params.primary_port is not None:
            if ( deployment.request( 'set_config', 
                                     { 'conf' : 'global/primary', 'value' : params.primary_domain, 'by' : session.email } ).isSuccess and
                 deployment.request( 'set_config', 
                                     { 'conf' : 'global/primary_port', 'value' : params.primary_port, 'by' : session.email } ).isSuccess ):
                session.notice = 'Success setting primary domain.'
            else:
                session.notice = 'Error setting primary domain.'
        elif params.secondary_domain is not None and params.secondary_port is not None:
            if ( deployment.request( 'set_config', 
                                     { 'conf' : 'global/secondary', 'value' : params.secondary_domain, 'by' : session.email } ).isSuccess and
                 deployment.request( 'set_config', 
                                     { 'conf' : 'global/secondary_port', 'value' : params.secondary_port, 'by' : session.email } ).isSuccess ):
                session.notice = 'Success setting secondary domain.'
            else:
                session.notice = 'Error setting secondary domain.'
        elif params.enrollmentsecret is not None:
            if deployment.request( 'set_config', 
                                   { 'conf' : 'global/enrollmentsecret', 'value' : params.enrollmentsecret, 'by' : session.email } ).isSuccess:
                session.notice = 'Success setting enrollment secret.'
            else:
                session.notice = 'Error setting enrollment secret.'
        elif params.paging_user is not None and params.paging_from is not None and params.paging_password is not None:
            if ( deployment.request( 'set_config', 
                                     { 'conf' : 'global/paging_user', 'value' : params.paging_user, 'by' : session.email } ).isSuccess and
                 deployment.request( 'set_config', 
                                     { 'conf' : 'global/paging_from', 'value' : params.paging_from, 'by' : session.email } ).isSuccess and
                 deployment.request( 'set_config', 
                                     { 'conf' : 'global/paging_password', 'value' : params.paging_password, 'by' : session.email } ).isSuccess ):
                session.notice = 'Success setting paging account.'
            else:
                session.notice = 'Error setting paging account.'
        elif params.virustotalkey is not None:
            if deployment.request( 'set_config', 
                                   { 'conf' : 'global/virustotalkey', 'value' : params.virustotalkey, 'by' : session.email } ).isSuccess:
                session.notice = 'Success setting VirusTotal key.'
            else:
                session.notice = 'Error setting VirusTotal key.'
        elif params.sensorpackage is not None:
            if deployment.request( 'set_config', 
                                   { 'conf' : 'global/sensorpackage', 'value' : params.sensorpackage, 'by' : session.email } ).isSuccess:
                session.notice = 'Success setting sensor package.'
            else:
                session.notice = 'Error setting sensor package.'
        elif params.uidomain is not None:
            if deployment.request( 'set_config', 
                                   { 'conf' : 'global/uidomain', 'value' : params.uidomain, 'by' : session.email } ).isSuccess:
                session.notice = 'Success setting ui domain.'
                DOMAIN_NAME = params.uidomain
            else:
                session.notice = 'Error setting ui domain.'
        elif params.whatsnew is not None:
            if deployment.request( 'set_config', 
                                   { 'conf' : 'global/whatsnew', 'value' : params.whatsnew, 'by' : session.email } ).isSuccess:
                session.notice = 'Success setting whatsnew.'
            else:
                session.notice = 'Error setting whatsnew.'
        elif params.outagetext is not None:
            if deployment.request( 'set_config', 
                                   { 'conf' : 'global/outagetext', 'value' : params.outagetext, 'by' : session.email } ).isSuccess:
                session.notice = 'Success setting outagetext.'
                outageState = '1' if params.outagestate is not None else '0'
                if deployment.request( 'set_config', 
                                       { 'conf' : 'global/outagestate', 'value' : outageState, 'by' : session.email } ).isSuccess:
                    session.notice = 'Success setting outagestate.'
                else:
                    session.notice = 'Error setting outagestate.'
            else:
                session.notice = 'Error setting outagetext.'
        elif params.policy is not None:
            if deployment.request( 'set_config', 
                                   { 'conf' : 'global/policy', 'value' : params.policy, 'by' : session.email } ).isSuccess:
                session.notice = 'Success setting policy.'
            else:
                session.notice = 'Error setting policy.'
        elif params.sendmetrics is not None:
            sendmetrics = '1' if params.sendmetrics is not None else '0'
            if deployment.request( 'set_config', 
                                   { 'conf' : 'global/send_metrics', 'value' : sendmetrics, 'by' : session.email } ).isSuccess:
                session.notice = 'Success setting metrics upload.'
            else:
                session.notice = 'Error setting metrics upload.'

        redirectTo( 'configs' )

class SensorConfigs ( AuthenticatedPage ):
    def doGET( self ):
        params = web.input()

        profiles = {}

        info = deployment.request( 'get_supported_events', {} )
        if not info.isSuccess:
            return renderAlone.error( 'error fetching supported events' )
        supportedEvents = info.data

        for oid in session.orgs:
            info = deployment.request( 'get_profiles', { 'oid' : oid, 'is_human_readable' : True } )

            if not info.isSuccess:
                return renderAlone.error( 'Could not get profiles: %s' % str( info ) )
            profiles[ oid ] = info.data

        cards = []
        for oid, p in profiles.iteritems():
            for pName, pContent in p.iteritems():
                parsedProfile = {}
                if pContent is None: continue
                for conf in pContent:
                    parsedProfile[ conf[ 'hbs.CONFIGURATION_ID' ] ] = conf
                cards.append( renderAlone.card_sensor_profile( pName, oid, getOrgName( oid )[ str( oid ) ], parsedProfile, supportedEvents ) )

        return render.sensor_profiles( cards )

    def doPOST( self ):
        params = web.input( oid = None, 
                            platform = None,
                            col = [],
                            exfil = [],
                            os_delta = 0 )

        oid = uuid.UUID( params.oid )
        if not isOrgAllowed( oid ):
            return renderAlone.error( 'Unauthorized.' )

        if params.platform is None:
            return renderAlone.error( 'Missing platform.' )

        onOrOff = {}
        for colId in HbsCollectorId.lookup.iterkeys():
            if colId not in map( int, params.col ):
                onOrOff[ colId ] = False
            else:
                onOrOff[ colId ] = True

        exfil = {}
        for eventId in map( int, params.exfil ):
            exfil[ eventId ] = True

        info = deployment.request( 'update_profile', { 'oid' : oid, 
                                                       'platform' : params.platform, 
                                                       'collectors' : onOrOff,
                                                       'exfil' : exfil,
                                                       'os_delta' : int( params.os_delta ) } )
        if not info.isSuccess:
            session.notice = 'Error updating profile: %s' % info
        else:
            session.notice = 'Success updating profile'

        redirectTo( 'sensor_configs' )

class SensorBandwidth ( AuthenticatedPage ):
    @jsonApi
    def doGET( self ):
        params = web.input( sensor_id = None )

        if params.sensor_id is None:
            raise web.HTTPError( '400 Bad Request: sensor id required' )

        info = model.request( 'get_sensor_info', { 'id_or_host' : params.sensor_id } )

        if not isOrgAllowed( AgentId( info.data[ 'id' ] ).org_id ):
            raise web.HTTPError( '401 Unauthorized' )

        usage = model.request( 'get_sensor_bandwidth', { 'sid' : params.sensor_id } )
        if not usage.isSuccess:
            raise web.HTTPError( '503 Service Unavailable: %s' % str( usage ) )

        return usage.data

class SensorIpUse ( AuthenticatedPage ):
    @jsonApi
    def doGET( self ):
        params = web.input( ip = None, before = None, after = None )

        usage = model.request( 'get_ip_usage', { 'ip' : params.ip, 
                                                 'after' : params.after, 
                                                 'before' : params.before, 
                                                 'oid' : session.orgs } )
        if not usage.isSuccess:
            raise web.HTTPError( '503 Service Unavailable: %s' % str( usage ) )

        usage.data[ 'usage' ] = sorted( usage.data[ 'usage' ], key = lambda x: x[ 0 ], reverse = True )

        return usage.data

class FindHost ( AuthenticatedPage ):
    def doGET( self ):
        params = web.input()

        return render.find_host()

class ObjInstance ( AuthenticatedPage ):
    def doGET( self ):
        params = web.input( oid = None )

        if params.oid is None:
            return renderAlone.error( 'need to supply an oid' )

        instances = model.request( 'get_obj_instances', { 'oid' : params.oid, 'orgs' : session.orgs } )

        if instances.isSuccess and 0 != len( instances.data ) and 0 != len( instances.data[ 'instances' ] ):
            hostnames = getHostnames( [ x[ 1 ] for x in instances.data[ 'instances' ] ] )
            return render.obj_instance( instances.data[ 'instances' ], hostnames )
        elif not instances.isSuccess:
            session.notice = 'Error fetching instances: %s' % str( instances )
        else:
            session.notice = 'No instances found.'
        
        redirectTo( '' )

class AddTag ( AuthenticatedPage ):
    @jsonApi
    def doPOST( self ):
        params = web.input( sid = None, tag = None )

        if params.sid is None:
            raise web.HTTPError( '400 Bad Request: sid required' )

        if params.tag is None:
            raise web.HTTPError( '400 Bad Request: tag required' )

        if not isSensorAllowed( params.sid ):
            raise web.HTTPError( '401 Unauthorized' )

        resp = tagging.request( 'add_tags', { 'sid' : AgentId( params.sid ).sensor_id, 
                                              'tag' : params.tag,
                                              'by' : session.email,
                                              'ttl' : ( 60 * 60 * 24 * 365 * 100 ) } )
        if resp.isSuccess:
            return { 'success' : True }
        else:
            raise web.HTTPError( '503 Service Unavailable: %s' % str( resp ) )

class DelTag ( AuthenticatedPage ):
    @jsonApi
    def doPOST( self ):
        params = web.input( sid = None, tag = None )

        if params.sid is None:
            raise web.HTTPError( '400 Bad Request: sid required' )

        if params.tag is None:
            raise web.HTTPError( '400 Bad Request: tag required' )

        if not isSensorAllowed( params.sid ):
            raise web.HTTPError( '401 Unauthorized' )

        resp = tagging.request( 'del_tags', { 'sid' : AgentId( params.sid ).sensor_id, 
                                              'tag' : params.tag,
                                              'by' : session.email } )
        if resp.isSuccess:
            return { 'success' : True }
        else:
            raise web.HTTPError( '503 Service Unavailable: %s' % str( resp ) )

class DelSensor ( AuthenticatedPage ):
    def doPOST( self ):
        params = web.input( sid = None )

        try:
            sid = AgentId( params.sid ).sensor_id
        except:
            sid = None

        if sid is None:
            session.notice = 'Invalid sid to delete provided.'
            redirectTo( '' )

        if not isSensorAllowed( sid ):
            raise web.HTTPError( '401 Unauthorized' )

        resp = deployment.request( 'del_sensor', { 'sid' : sid } )
        if resp.isSuccess:
            session.notice = 'Sensor deleted.'
        else:
            session.notice = str( resp )
        redirectTo( 'sensors' )


#==============================================================================
#   CARDS
#==============================================================================
def card_sensor_stats( name, sensors, oid ):
    return renderAlone.card_sensor_stats( sensors, name, oid )

def card_org_membership( name, oid ):
    members = []
    res = identmanager.request( 'get_org_members', { 'oid' : oid } )
    if res.isSuccess:
        for uid, email in res.data[ 'orgs' ][ oid ].iteritems():
            members.append( ( email, uid ) )
    return renderAlone.card_org_membership( name, members )

def card_org_retention( name, oid, ttls ):
    return renderAlone.card_org_retention( name, ttls )

def card_sensors( name, sensors ):
    return renderAlone.card_sensors( sensors, name )

def card_sensor_ident( aid, hostname, orgName, tags ):
    return renderAlone.card_sensor_ident( aid, hostname, orgName, tags )

def card_sensor_traffic( aid, hostname, after, before ):
    return renderAlone.card_sensor_traffic( aid, hostname, after, before )

def card_event_explorer( eid ):
    return renderAlone.card_event_explorer( eid )

def card_event( event, atom ):
    return renderAlone.card_event( event, atom )

def card_objsummary( oid, oname, otype ):
    return renderAlone.card_objsummary( oid, oname, otype )

def card_object( oid, oname, otype, olocs, locs, rlocs, parents, children, sid, hostnames ):
    return renderAlone.card_object( oid, oname, otype, olocs, locs, rlocs, parents, children, sid, hostnames )

def card_sensor_last( aid, hostname ):
    return renderAlone.card_sensor_last( aid, hostname )

def card_sensor_changes( aid, hostname ):
    return renderAlone.card_sensor_changes( aid, hostname )

def card_sensor_bandwidth( aid, hostname ):
    return renderAlone.card_sensor_bandwidth( aid, hostname )

#==============================================================================
#   START
#==============================================================================
if __name__ == '__main__':
    app.run()

application = app.wsgifunc()
