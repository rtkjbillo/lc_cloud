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
import traceback
import hashlib
import time
import ipaddress
CassDb = Actor.importLib( 'utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( 'utils/hcp_databases', 'CassPool' )
rpcm = Actor.importLib( 'utils/rpcm', 'rpcm' )
rList = Actor.importLib( 'utils/rpcm', 'rList' )
rSequence = Actor.importLib( 'utils/rpcm', 'rSequence' )
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )
Mutex = Actor.importLib( 'utils/hcp_helpers', 'Mutex' )

class EnrollmentRule( object ):
    def __init__( self, parent, aid, extIp, intIp, hostName, newOrg, newSubnet ):
        self._parent = parent
        self._aid = AgentId( aid )
        self._extIp = ipaddress.ip_network( unicode( extIp ) )
        self._intIp = ipaddress.ip_network( unicode( intIp ) )
        self._hostName = hostName
        self._newOrg = newOrg
        self._newSubnet = newSubnet

    def isMatch( self, aid, extIp, intIp, hostName ):
        extIp = ipaddress.ip_network( unicode( extIp ) )
        intIp = ipaddress.ip_network( unicode( intIp ) )

        if not AgentId( aid ).inSubnet( self._aid ):
            return False
        if not self._extIp.overlaps( extIp ):
            return False
        if not self._intIp.overlaps( intIp ):
            return False
        if ( self._hostName is not None and self._hostName != '' and 
             ( hostName is None or self._hostName.lower() == hostName.lower() ) ):
            return False
        return ( self._newOrg, self._newSubnet )


class EnrollmentManager( Actor ):
    def init( self, parameters, resources ):
        self._db = CassDb( parameters[ 'db' ], 'hcp_analytics', consistencyOne = True )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )

        self.rules = []
        self.states = {}

        self.lock = Mutex()

        self.db.start()

        self.loadRules()
        self.loadEnrollmentState()

        self.handle( 'enroll', self.enroll )
        self.handle( 'reload', self.loadRules )

    def deinit( self ):
        pass

    def loadEnrollmentState( self ):
        self.lock.lock()
        try:
            states = {}
            for row in self.db.execute( 'SELECT org, subnet, unique FROM sensor_states' ):
                if row[ 2 ] > states.setdefault( row[ 0 ], {} ).setdefault( row[ 1 ], 0 ):
                    states[ row[ 0 ] ][ row[ 1 ] ] = row[ 2 ]
            self.states = states
        finally:
            self.lock.unlock()

    def loadRules( self, msg = None ):
        newRules = []
        for row in self.db.execute( 'SELECT aid, ext_ip, int_ip, hostname, new_org, new_subnet FROM enrollment' ):
            newRules.append( EnrollmentRule( self, row[ 0 ], row[ 1 ], row[ 2 ], row[ 3 ], row[ 4 ], row[ 5 ] ) )
        self.rules = newRules

    def getUniqueFor( self, org, subnet, platform ):
        self.lock.lock()
        try:
            newUnique = self.states.setdefault( org, {} ).setdefault( subnet, 0 ) + 1
            self.db.execute( 'INSERT INTO sensor_states ( org, subnet, unique, platform, enroll ) VALUES ( %s, %s, %s, %s, dateOf( now() ) )', 
                             ( org, subnet, newUnique, platform ) )
            self.states[ org ][ subnet ] = newUnique
        finally:
            self.lock.unlock()
        return newUnique

    def enroll( self, msg ):
        req = msg.data

        aid = AgentId( req[ 'aid' ] )
        extIp = req[ 'public_ip' ]
        intIp = req[ 'internal_ip' ]
        hostName = req[ 'host_name' ]

        newAid = None

        for rule in self.rules:
            tmpAid = rule.isMatch( aid, extIp, intIp, hostName )
            if tmpAid is not False:
                aid.org = tmpAid[ 0 ]
                aid.subnet = tmpAid[ 1 ]
                aid.unique = self.getUniqueFor( aid.org, aid.subnet, aid.platform )
                newAid = aid
                self.log( 'enrolling new sensor to %s' % aid.invariableToString() )
                break
        else:
            self.log( 'no enrollment rules matched' )

        return ( True, { 'aid' : newAid } )