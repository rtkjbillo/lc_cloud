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

class VirusTotalActor ( Actor ):
    def init( self, parameters, resources ):
        self.key = parameters.get( '_key', None )
        if self.key is None: self.logCritical( 'missing API key' )

        # Maximum number of queries per minute
        self.qpm = parameters.get( 'qpm', 4 )
        self.ttl = parameters.get( 'ttl', ( 60 * 60 * 24 * 7 ) )

        if self.key is not None:
            self.vt = virustotal.VirusTotal( self.key, limit_per_min = self.qpm )

        self.Model = self.getActorHandle( resources[ 'modeling' ], timeout = 3, nRetries = 0 )

        # Cache size
        self.cache_size = parameters.get( 'cache_size', 5000 )

        self.cache = RingCache( maxEntries = self.cache_size, isAutoAdd = False )

        self.handle( 'get_report', self.getReport )

    def deinit( self ):
        pass

    def getReportFromCache( self, fileHash ):
        report = False

        # First level of cache is in memory.
        if fileHash in self.cache:
            report = self.cache.get( fileHash )

        # Second level of cache is in the key value store.
        if report is False:
            resp = self.Model.request( 'get_kv', { 'cat' : 'vt', 'k' : fileHash } )
            if resp.isSuccess:
                try:
                    report = json.loads( resp.data[ 'v' ] )
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

        if not all( x in "1234567890abcdef" for x in fileHash.lower() ) and len( fileHash ) in [ 32, 40, 64 ]:
            fileHash = fileHash.encode( 'hex' )
        fileHash = fileHash.lower()

        report = self.getReportFromCache( fileHash )
        if report is False:
            report = None
            vtReport = None
            nRetry = 3
            while True:
                try:
                    vtReport = self.vt.get( fileHash )
                except:
                    self.log( 'VT API failure, retrying.' )
                    if 0 == nRetry:
                        return ( False, 'API failure' )
                    nRetry -= 1
                else:
                    break
            if vtReport is not None:
                report = {}
                for av, r in vtReport:
                    report[ ','.join( av  ) ] = r
                self.recordNewReport( fileHash, report )

        return ( True, { 'report' : report, 'hash' : fileHash } )
