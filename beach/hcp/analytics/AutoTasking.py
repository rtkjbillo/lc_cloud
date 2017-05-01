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
ArgumentParserError = Actor.importLib( '../admin_cli', 'ArgumentParserError' )
CassDb = Actor.importLib( 'utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( 'utils/hcp_databases', 'CassPool' )
AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )
RingCache = Actor.importLib( 'utils/hcp_helpers', 'RingCache' )

class AutoTasking( Actor ):
    def init( self, parameters, resources ):
        self.authToken = parameters.get( 'auth_token', '' )
        self.cmdLogFile = parameters.get( 'log_file', None )

        self._db = CassDb( parameters[ 'db' ], 'hcp_analytics', consistencyOne = True )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )

        self.get_key_stmt = self.db.prepare( 'SELECT data FROM hbs_keys WHERE oid = ?' )

        self.db.start()

        self.sensor_qph = parameters.get( 'sensor_qph', 50 )
        self.global_qph = parameters.get( 'global_qph', 200 )
        self.allowed_commands = Set( parameters.get( 'allowed', [] ) )
        self.model = self.getActorHandle( resources[ 'modeling' ] )
        self.handle( 'task', self.handleTasking )
        self.sensor_stats = {}
        self.global_stats = 0
        self.iface_cache = RingCache( 3 )
        self.schedule( 3600, self.decay )

    def deinit( self ):
        pass

    def getCli( self, oid ):
        key = None
        cli = None

        try:
            cli = self.iface_cache.get( oid )
            self.log( "Got org key for %s from cache." % oid )
        except:
            cli = None

        if cli is None:
            for row in self.db.execute( self.get_key_stmt.bind( ( oid, ) ) ):
                key = row[ 0 ]
                break
            if key is not None:
                cli = HcpCli( self._beach_config_path,
                              self.authToken,
                              key,
                              self.cmdLogFile )
                self.iface_cache.add( oid, cli )
                self.log( "Got org key for %s from storage." % oid )
        return cli

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

        oid = AgentId( agentid ).org_id
        if oid is None:
            resp = self.model.request( 'get_sensor_info', { 'id_or_host' : agentid } )
            if resp.isSuccess:
                oid = AgentId( resp.data[ 'id' ] ).org_id

        cli = self.getCli( oid )

        if cli is None:
            self.log( 'Could not task, we have no keys for org %s' % ( str( oid ), ) )
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
                try:
                    self.execTask( task, dest, expiry = expiry, invId = invId )
                except ArgumentParserError as e:
                    return ( False, 'usage', str( e ) )

        return ( True, )