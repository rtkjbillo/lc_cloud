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
CreateOnAccess = Actor.importLib( '../utils/hcp_helpers', 'CreateOnAccess' )

class VirusTotalActor ( Actor ):
    def init( self, parameters, resources ):
        self.deploymentManager = CreateOnAccess( self.getActorHandle, resources[ 'deployment' ], nRetries = 3, timeout = 30 )
        self.key = parameters.get( '_key', None )
        
        # Maximum number of queries per minute
        self.qpm = parameters.get( 'qpm', 4 )
        self.ttl = parameters.get( 'ttl', ( 60 * 60 * 24 * 7 ) )

        if self.key is None:
            self.refreshCredentials()
            self.log( 'got virustotal key from deployment manager' )
        else:
            self.log( 'got virustotal key from parameters' )
            self.vt = virustotal.VirusTotal( self.key, limit_per_min = self.qpm )

        if self.key is None: self.logCritical( 'missing API key' )

        self.vtMutex = Mutex()

        self.Model = self.getActorHandle( resources[ 'modeling' ], timeout = 10, nRetries = 5 )

        # Cache size
        self.cache_size = parameters.get( 'cache_size', 5000 )

        self.cache = RingCache( maxEntries = self.cache_size, isAutoAdd = False )

        self.handle( 'get_report', self.getReport )

    def deinit( self ):
        pass

    def refreshCredentials( self ):
        resp = self.deploymentManager.request( 'get_global_config', {} )
        if resp.isSuccess:
            oldKey = self.key
            self.key = resp.data[ 'global/virustotalkey' ]
            if '' == self.key:
                self.key = None
            elif oldKey != self.key:
                self.log( 'new credentials' )
                self.vt = virustotal.VirusTotal( self.key, limit_per_min = self.qpm )

        self.delay( 60, self.refreshCredentials )

    def getReportFromCache( self, fileHash ):
        report = False

        # First level of cache is in memory.
        if fileHash in self.cache:
            report = self.cache.get( fileHash )
            self.zInc( 'lvl_1_hit' )

        # Second level of cache is in the key value store.
        if report is False:
            resp = self.Model.request( 'get_kv', { 'cat' : 'vt', 'k' : fileHash } )
            if resp.isSuccess:
                try:
                    report = json.loads( resp.data[ 'v' ] )
                    self.zInc( 'lvl_2_hit' )
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
        isCacheOnly = msg.data.get( 'cache_only', False )

        if not all( x in "1234567890abcdef" for x in fileHash.lower() ) and len( fileHash ) in [ 32, 40, 64 ]:
            fileHash = fileHash.encode( 'hex' )
        fileHash = fileHash.lower()

        self.zInc( 'total_q' )

        if not isNoCache:
            report = self.getReportFromCache( fileHash )
        else:
            report = False
        if report is False or isCacheOnly:
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
                self.zInc( 'vt_q' )

        return ( True, { 'report' : report, 'hash' : fileHash } )

