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

from sets import Set

HcpCli = Actor.importLib( '../admin_cli', 'HcpCli' )
CassDb = Actor.importLib( 'utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( 'utils/hcp_databases', 'CassPool' )
AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )

class AutoTasking( Actor ):
    def init( self, parameters, resources ):
        self.hbs_ifaces = {}

        self.authToken = parameters.get( 'auth_token', '' )
        self.cmdLogFile = parameters.get( 'log_file', None )

        self._db = CassDb( parameters[ 'db' ], 'hcp_analytics', consistencyOne = True )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )

        self.db.start()

        self.refreshKeys()

        self.sensor_qph = parameters.get( 'sensor_qph', 50 )
        self.global_qph = parameters.get( 'global_qph', 200 )
        self.allowed_commands = Set( parameters.get( 'allowed', [] ) )
        self.handle( 'task', self.handleTasking )
        self.sensor_stats = {}
        self.global_stats = 0
        self.schedule( 3600, self.decay )
        self.schedule( 3600, self.refreshKeys )

    def deinit( self ):
        pass

    def refreshKeys( self ):
        orgs = self.db.execute( 'SELECT oid, data FROM hbs_keys' )
        if orgs is None or orgs is False:
            raise Exception( 'Could not fetch hbs keys' )

        for row in orgs:
            self.hbs_ifaces[ str( row[ 0 ] ) ] = HcpCli( self._beach_config_path,
                                                  self.authToken,
                                                  row[ 1 ],
                                                  self.cmdLogFile )
        self.log( "We now have the following keys loaded: %s" % ( self.hbs_ifaces.keys(), ) )

    def decay( self ):
        for k in self.sensor_stats.iterkeys():
            self.sensor_stats[ k ] = 0
        self.global_stats = 0

    def updateStats( self, sensorId, task ):
        self.sensor_stats.setdefault( sensorId, 0 )
        self.sensor_stats[ sensorId ] += 1
        self.global_stats += 1

    def isQuotaAllowed( self, sensorId, task ):
        isAllowed = False
        if task[ 0 ] in self.allowed_commands:
            if self.sensor_stats.get( sensorId, 0 ) < self.sensor_qph and self.global_stats < self.global_qph:
                self.updateStats( sensorId, task )
                isAllowed = True
            else:
                self.log( "could not execute tasking because of quota: sensor( %d / %d ) and global( %d / %d )" %
                          ( self.sensor_stats.get( sensorId ), self.sensor_qph,
                            self.global_stats, self.global_qph ) )
        else:
            self.log( "command %s not allowed for autotasking" % task[ 0 ] )

        return isAllowed

    def execTask( self, task, agentid, expiry = None, invId = None ):
        if expiry is None:
            expiry = 3600
        command = '%s %s -! %s -x %d' % ( task[ 0 ],
                                          ' '.join( [ '"%s"' % ( x, ) for x in task[ 1 : ] ] ),
                                          agentid,
                                          expiry )

        if invId is not None:
            command += ' -@ "%s"' % str( invId )

        cli = self.hbs_ifaces.get( str( AgentId( agentid ).org_id ), None )
        if cli is None:
            self.log( 'Could not task, we have no keys for org %s' % ( str( AgentId( agentid ).org_id ), ) )
        else:
            cli.onecmd( command )
            self.log( command )

    def handleTasking( self, msg ):
        dest = msg.data[ 'dest' ]
        tasks = msg.data.get( 'tasks', tuple() )
        expiry = msg.data.get( 'expiry', None )
        invId = msg.data.get( 'inv_id', None )

        sent = Set()

        for task in tasks:
            task = tuple( task )
            if task in sent: continue
            sent.add( task )

            if self.isQuotaAllowed( dest, task ):
                self.execTask( task, dest, expiry = expiry, invId = invId )

        return ( True, )