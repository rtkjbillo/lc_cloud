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

import time
import syslog
from beach.actor import Actor
import traceback
synchronized = Actor.importLib( './hcp_helpers', 'synchronized' )
from collections import deque
import gevent
import datetime
epoch = datetime.datetime.utcfromtimestamp( 0 )


from cassandra.cluster import Cluster
import traceback
from cassandra.query import SimpleStatement
from cassandra import ConsistencyLevel
from cassandra.query import ValueSequence

class CassDb( object ):

    CL_Ingest = ConsistencyLevel.ONE
    CL_Reliable = ConsistencyLevel.QUORUM
    CL_Default = ConsistencyLevel.TWO

    def __init__( self, url, dbname, version = '3.4.4', quorum = False, consistencyOne = False, backoffConsistency = False ):

        self.isShutdown = False
        self.url = url
        self.dbname = dbname
        self.version = version
        self.consistency = self.CL_Default
        self.cluster = Cluster( url, cql_version = version, control_connection_timeout = 30.0 )
        self.cur = self.cluster.connect( dbname )
        #self.cur.row_factory = tuple_factory
        self.cur.default_timeout = 30.0
        self.backoffConsistency = backoffConsistency

        if quorum:
            self.consistency = self.CL_Reliable
        elif consistencyOne:
            self.consistency = self.CL_Ingest

    def __del__( self ):
        self.shutdown()

    def execute( self, query, params = tuple() ):
        res = None

        thisCur = self.cur

        realParams = []
        for p in params:
            if type( p ) in ( list, tuple ):
                p = ValueSequence( p )
            realParams.append( p )

        def queryWith( stmt ):
            nRetry = 0
            isSuccess = False
            while ( not isSuccess ) and ( nRetry < 2 ):
                res = None
                try:
                    res = thisCur.execute( stmt, realParams )
                    isSuccess = True
                except Exception as e:
                    desc = traceback.format_exc()
                    if 'OperationTimedOut' not in desc:
                        raise e
                    else:
                        gevent.sleep( 5 )
                        syslog.syslog( syslog.LOG_USER, 'TIMEDOUT RETRYING' )
                        nRetry += 1
            return res

        if type( query ) is str or type( query ) is unicode:
            q = SimpleStatement( query, consistency_level = self.consistency )
        else:
            q = query

        try:
            res = queryWith( q )
        except:
            if self.backoffConsistency:
                if ( type( query ) is str or type( query ) is unicode ):
                    q = SimpleStatement( query, consistency_level = self.CL_Ingest )
                else:
                    q = query
                res = queryWith( q )
            else:
                raise

        return res

    def getOne( self, query, params = tuple() ):
        res = self.execute( query, params )
        if res is not None:
            try:
                res = res[ 0 ]
            except:
                res = None
        return res

    def prepare( self, query ):
        return self.cur.prepare( query )

    def execute_async( self, query, params = [] ):
        if type( query ) is str or type( query ) is unicode:
            query = SimpleStatement( query, consistency_level = self.consistency )
        realParams = []
        for p in params:
            if type( p ) in ( list, tuple ):
                p = ValueSequence( p )
            realParams.append( p )
        return self.cur.execute_async( query, realParams )

    def shutdown( self ):
        if not self.isShutdown:
            self.isShutdown = True
            self.cur.shutdown()
            self.cluster.shutdown()
            time.sleep( 0.5 )

    def timeToMsTs( self, t ):
        return ( t - epoch ).total_seconds() * 1000.0

class CassPool( object ):

    def __init__( self, db, maxConcurrent = 1, error_log_func = None, rate_limit_per_sec = None, blockOnQueueSize = None ):
        self.maxConcurrent = maxConcurrent
        self.db = db
        self.error_log = error_log_func
        self.isRunning = False
        self.rate_limit = rate_limit_per_sec
        self.rate = 0
        self.last_rate_time = 0
        self.blockOnQueueSize = blockOnQueueSize
        self.queries = deque()
        self.threads = gevent.pool.Group()
        for _ in range( self.maxConcurrent ):
            self._addHandler()

    @synchronized
    def rateLimit( self, isAdvisory = False ):
        limit = self.rate_limit
        if limit is not None:
            now = int( time.time() )
            if self.last_rate_time != now:
                self.last_rate_time = now
                self.rate = 0
            self.rate += 1
            if not isAdvisory and limit < self.rate:
                syslog.syslog( syslog.LOG_USER, 'RATE LIMIT' )
                gevent.sleep( 1 )
                self.rate = 0

    def execute_async( self, query, params = [] ):
        self.queries.append( ( query, params ) )
        while self.blockOnQueueSize is not None and len( self.queries ) > self.blockOnQueueSize:
            syslog.syslog( syslog.LOG_USER, 'BLOCKING' )
            gevent.sleep( 1 )

    def execute( self, query, params = tuple() ):
        self.rateLimit( isAdvisory = True )
        return self.db.execute( query, params )

    def _addHandler( self ):
        self.threads.add( gevent.spawn( self._queryThread ) )

    def _queryThread( self ):
        while True:
            while not self.isRunning:
                gevent.sleep( 1 )
            try:
                q = self.queries.popleft()
            except:
                q = None

            if q is not None:
                self.rateLimit()
                try:
                    self.db.execute( *q )
                    #syslog.syslog( syslog.LOG_USER, '+' )
                except:
                    syslog.syslog( syslog.LOG_USER, 'EXCEPTION: %s' % traceback.format_exc() )
            else:
                gevent.sleep( 1 )
                #syslog.syslog( syslog.LOG_USER, 'WAITING SUCCESS' )


    def start( self ):
        self.isRunning = True

    def stop( self):
        self.isRunning = False

    def numQueued( self ):
        return len( self.queries )

    def shutdown( self ):
        self.threads.join( timeout = 10 )
        self.threads.kill( timeout = 10 )
        return self.db.shutdown()

    def prepare( self, query ):
        return self.db.prepare( query )

    def getOne( self, query, params = {} ):
        self.rateLimit( isAdvisory = True )
        return self.db.getOne( query, params )

    def timeToMsTs( self, t ):
        return self.db.timeToMsTs( t )