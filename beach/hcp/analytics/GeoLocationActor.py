# Copyright 2017 Google, Inc
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
import time
import urllib2
import json

class GeoLocationActor( Actor ):
    def init( self, parameters, resources ):
        self.url = 'http://ip-api.com/json/%s'
        self.handle( 'locate_ip', self.locateIp )

    def deinit( self ):
        pass

    def locateIp( self, msg ):
        ip = msg.data[ 'ip' ]

        result = json.loads( urllib2.urlopen( urllib2.Request( self.url % ip, headers = { 'User-Agent': 'LimaCharlie' } ) ).read() )

        if 'success' != result[ 'status' ]:
            return ( False, 'geolocation api call failed: %s' % result[ 'message' ] )
        
        return ( True, { 'geo' : result } )
