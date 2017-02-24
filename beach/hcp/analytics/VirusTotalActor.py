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
import virustotal
import json
RingCache = Actor.importLib( '../utils/hcp_helpers', 'RingCache' )
Mutex = Actor.importLib( '../utils/hcp_helpers', 'Mutex' )

class VirusTotalActor ( Actor ):
    def init( self, parameters, resources ):
        self.key = parameters.get( '_key', None )
        if self.key is None: self.logCritical( 'missing API key' )

        # Maximum number of queries per minute
        self.qpm = parameters.get( 'qpm', 4 )
        self.ttl = parameters.get( 'ttl', ( 60 * 60 * 24 * 7 ) )

        if self.key is not None:
            self.vt = virustotal.VirusTotal( self.key, limit_per_min = self.qpm )
        self.vtMutex = Mutex()

        self.Model = self.getActorHandle( resources[ 'modeling' ], timeout = 3, nRetries = 0 )

        # Cache size
        self.cache_size = parameters.get( 'cache_size', 5000 )

        self.cache = RingCache( maxEntries = self.cache_size, isAutoAdd = False )

        self.stats = [ 0, 0, 0, 0 ]
        self.schedule( 60 * 60, self.wipeStats )
        self.schedule( 60 * 5, self.reportStats )

        self.handle( 'get_report', self.getReport )

    def deinit( self ):
        pass

    def wipeStats( self ):
        self.stats = [ 0, 0, 0, 0 ]

    def reportStats( self ):
        self.log( "VT Stats - Total: %s, Lvl1Cache: %s, Lvl2Cache: %s, VTAPI: %s" % tuple( self.stats ) )

    def getReportFromCache( self, fileHash ):
        report = False

        # First level of cache is in memory.
        if fileHash in self.cache:
            report = self.cache.get( fileHash )
            self.stats[ 1 ] += 1

        # Second level of cache is in the key value store.
        if report is False:
            resp = self.Model.request( 'get_kv', { 'cat' : 'vt', 'k' : fileHash } )
            if resp.isSuccess:
                try:
                    report = json.loads( resp.data[ 'v' ] )
                    self.stats[ 2 ] += 1
                except:
                    report = False

        return report

    def recordNewReport( self, fileHash, report ):
        # Set it in memory.
        self.cache.add( fileHash, report )
        # Set it in key value store.
        resp = self.Model.request( 'set_kv', { 'cat' : 'vt', 
                                               'k' : fileHash, 
                                               'v' : json.dumps( report ), 
                                               'ttl' : self.ttl } )
        if not resp.isSuccess:
            self.log( 'error storing new report in key value store' )

    def getReport( self, msg ):
        if self.key is None: return ( False, 'no key set' )

        fileHash = msg.data.get( 'hash', None )
        if fileHash is None: return ( False, 'missing hash' )

        isNoCache = msg.data.get( 'no_cache', False )

        if not all( x in "1234567890abcdef" for x in fileHash.lower() ) and len( fileHash ) in [ 32, 40, 64 ]:
            fileHash = fileHash.encode( 'hex' )
        fileHash = fileHash.lower()

        self.stats[ 0 ] += 1

        report = self.getReportFromCache( fileHash )
        if report is False or isNoCache:
            report = None
            vtReport = None
            nRetry = 3
            while True:
                self.vtMutex.lock()
                try:
                    vtReport = self.vt.get( fileHash )
                except:
                    self.log( 'VT API failure, retrying.' )
                    if 0 == nRetry:
                        return ( False, 'API failure' )
                    nRetry -= 1
                else:
                    break
                finally:
                    self.vtMutex.unlock()
            if vtReport is not None:
                report = {}
                for av, r in vtReport:
                    report[ str( av ) ] = r
                self.recordNewReport( fileHash, report )
                self.stats[ 3 ] += 1

        return ( True, { 'report' : report, 'hash' : fileHash } )

