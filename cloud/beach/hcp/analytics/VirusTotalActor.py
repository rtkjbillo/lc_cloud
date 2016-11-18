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
RingCache = Actor.importLib( '../utils/hcp_helpers', 'RingCache' )

class VirusTotalActor ( Actor ):
    def init( self, parameters, resources ):
        self.key = parameters.get( '_key', None )
        if self.key is None: self.logCritical( 'missing API key' )

        # Maximum number of queries per minute
        self.qpm = parameters.get( 'qpm', 4 )

        if self.key is not None:
            self.vt = virustotal.VirusTotal( self.key, limit_per_min = self.qpm )

        # Cache size
        self.cache_size = parameters.get( 'cache_size', 1000 )

        self.cache = RingCache( maxEntries = self.cache_size, isAutoAdd = False )

        self.handle( 'get_report', self.getReport )

        # Todo: move from RingCache to using Cassandra as larger cache

    def deinit( self ):
        pass

    def getReport( self, msg ):
        if self.key is None: return ( False, 'no key set' )

        fileHash = msg.data.get( 'hash', None )
        if fileHash is None: return ( False, 'missing hash' )

        if not all( x in "1234567890abcdef" for x in fileHash.lower() ) and len( fileHash ) in [ 32, 40, 64 ]:
            fileHash = fileHash.encode( 'hex' )
        fileHash = fileHash.lower()

        if fileHash not in self.cache:
            retries = 0
            report = None
            while retries < 3:
                vtReport = self.vt.get( fileHash )
                if vtReport is not None:
                    report = {}
                    for av, r in vtReport:
                        report[ av ] = r
                    break
            if report is None: return ( False, 'API error' )
        else:
            report = self.cache.get( fileHash )

        self.cache.add( fileHash, report )

        return ( True, { 'report' : report, 'hash' : fileHash } )
