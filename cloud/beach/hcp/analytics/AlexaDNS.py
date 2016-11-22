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
import urllib2
from zipfile import ZipFile
from StringIO import StringIO

class AlexaDNS ( Actor ):
    def init( self, parameters, resources ):
        self.domain = 'htts://statvoo.com/dl/top-1million-sites.csv.zip'
        self.topMap = {}
        self.topList = []
        self.refreshDomains()
        self.handle( 'get_list', self.getList )
        self.handle( 'is_in_top', self.isInTop )

    def deinit( self ):
        pass

    def refreshDomains( self ):
        response = urllib2.urlopen( self.domain ).read()
        z = ZipFile( StringIO( response ) )
        content = z.read( z.namelist()[ 0 ] )
        newMap = {}
        newList = []
        for d in content.split( '\n' ):
            if '' == d: continue
            n, dns = d.split( ',' )
            newMap[ dns ] = int( n )
            newList.append( dns )
        self.topMap = newMap
        self.topList = newList
        self.log( "updated Alexa top list with %d domains." % len( self.topList ) )
        self.delay( 60 * 60 * 24, self.refreshDomains )

    def getList( self, msg ):
        topN = msg.data.get( 'n', 1000000 )
        return ( True, { 'domains' : self.topList[ : topN ] } )

    def isInTop( self, msg ):
        domain = msg.data[ 'domain' ]
        if domain in self.topMap:
            return ( True, { 'n' : self.topMap[ domain ] } )
        else:
            return ( True, { 'n' : None } )