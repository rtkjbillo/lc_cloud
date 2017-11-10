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
from cassandra.policies import ConstantReconnectionPolicy
from cassandra.policies import ConstantSpeculativeExecutionPolicy
epoch = datetime.datetime.utcfromtimestamp( 0 )


from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement
from cassandra import ConsistencyLevel
from cassandra.query import ValueSequence

class CassDb( object ):

    def __init__( self, url, dbname, consistency = None ):

        self.isShutdown = False
        self.url = url
        self.dbname = dbname
        self.nSuccess = 0
        self.nErrors = 0
        self.nActive = 0
        self.consistency = ConsistencyLevel.ONE if consistency is None else consistency
        self.cluster = Cluster( url, 
                                control_connection_timeout = 30.0, 
                                reconnection_policy = ConstantReconnectionPolicy( 15.0, max_attempts = None ),
                                default_retry_policy = ConstantSpeculativeExecutionPolicy( 30, 10 ) )
        self.cur = self.cluster.connect( dbname )
        self.cur.default_timeout = 30.0

    def __del__( self ):
        self.shutdown()

    def _logError( self, exception, failureCallback, query, params ):
        self.nActive -= 1
        self.nErrors += 1
        if failureCallback is not None:
            failureCallback( query, params )

    def _logSuccess( self, rows ):
        self.nActive -= 1
        self.nSuccess += 1

    def execute( self, query, params = tuple() ):
        res = None

        realParams = []
        for p in params:
            if type( p ) in ( list, tuple ):
                p = ValueSequence( p )
            realParams.append( p )

        if type( query ) is str or type( query ) is unicode:
            q = SimpleStatement( query, consistency_level = self.consistency )
        else:
            q = query

        try:
            res = self.cur.execute( q, realParams )
        except Exception as e:
            self._logError( e, None, q, realParams )
            raise
        else:
            self._logSuccess( res )

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

    def execute_async( self, query, params = [], failureCallback = None ):
        if type( query ) is str or type( query ) is unicode:
            query = SimpleStatement( query, consistency_level = self.consistency )
        realParams = []
        for p in params:
            if type( p ) in ( list, tuple ):
                p = ValueSequence( p )
            realParams.append( p )

        self.nActive += 1
        future = self.cur.execute_async( query, realParams )
        future.add_callbacks( callback = self._logSuccess, 
                              errback = self._logError,
                              errback_args = ( failureCallback, query, realParams ) )

        return future

    def shutdown( self ):
        if not self.isShutdown:
            self.isShutdown = True
            try:
                self.cur.shutdown()
                self.cluster.shutdown()
            except:
                pass
            time.sleep( 0.5 )

    def timeToMsTs( self, t ):
        return ( t - epoch ).total_seconds() * 1000.0

    def isActive( self ):
        return 0 == self.nActive
