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
CassDb = Actor.importLib( 'utils/hcp_databases', 'CassDb' )
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )

class StateUpdater( Actor ):
    def init( self, parameters, resources ):
        self.db = CassDb( parameters[ 'db' ], 'hcp_analytics' )

        self.recordLive = self.db.prepare( 'UPDATE sensor_states SET alive = dateOf(now()), ext_ip = ?, int_ip = ?, hostname = ?, oid = ?, iid = ?, plat = ?, arch = ? WHERE sid = ?' )
        self.recordHostName = self.db.prepare( 'INSERT INTO sensor_hostnames ( hostname, sid ) VALUES ( ?, ? ) USING TTL %s' % ( 60 * 60 * 24 * 30 ) )
        self.recordDead = self.db.prepare( 'UPDATE sensor_states SET dead = dateOf(now()) WHERE sid = ?' )
        self.recordTraffic = self.db.prepare( 'INSERT INTO sensor_transfer ( sid, ts, b ) VALUES ( ?, dateOf(now()), ? ) USING TTL %s' % ( 60 * 60 * 24 * 7 ) )
        self.recordStateChange = self.db.prepare( 'INSERT INTO sensor_ip ( oid, sid, ts, ip ) VALUES ( ?, ?, dateOf(now()), ? ) USING TTL %s' % ( 60 * 60 * 24 * 30 ) )

        self.handle( 'live', self.setLive )
        self.handle( 'dead', self.setDead )
        self.handle( 'transfered', self.addTransfered )

    def deinit( self ):
        self.db.shutdown()

    def setLive( self, msg ):
        aid = AgentId( msg.data[ 'aid' ] )
        extIp = msg.data[ 'ext_ip' ]
        intIp = msg.data[ 'int_ip' ]
        hostName = msg.data[ 'hostname' ]

        self.db.execute_async( self.recordLive.bind( ( extIp, intIp, hostName, aid.org_id, aid.ins_id, aid.platform, aid.architecture, aid.sensor_id ) ) )
        self.db.execute_async( self.recordHostName.bind( ( hostName.upper(), aid.sensor_id ) ) )
        self.db.execute_async( self.recordStateChange.bind( ( aid.org_id, aid.sensor_id, extIp ) ) )
        self.db.execute_async( self.recordStateChange.bind( ( aid.org_id, aid.sensor_id, intIp ) ) )
        return ( True, )

    def setDead( self, msg ):
        aid = AgentId( msg.data[ 'aid' ] )
        self.db.execute_async( self.recordDead.bind( ( aid.sensor_id, ) ) )
        return ( True, )

    def addTransfered( self, msg ):
        aid = AgentId( msg.data[ 'aid' ] )
        newBytes = msg.data[ 'bytes_transfered' ]
        self.db.execute_async( self.recordTraffic.bind( ( aid.sensor_id, newBytes ) ) )
        return ( True, )