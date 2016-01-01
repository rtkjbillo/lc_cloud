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

class AutoTasking( Actor ):
    def init( self, parameters ):
        self.hbs_key = parameters.get( '_hbs_key', None )
        if self.hbs_key is None: raise Exception( 'missing HBS key' )
        self.cli = HcpCli( parameters[ 'beach_config' ],
                           parameters.get( 'auth_token', '' ),
                           self.hbs_key,
                           parameters.get( 'log_file', None ) )
        self.sensor_qph = parameters.get( 'sensor_qph', 10 )
        self.global_qph = parameters.get( 'global_qph', 100 )
        self.allowed_commands = Set( parameters.get( 'allowed', [] ) )
        self.handle( 'task', self.handleTasking )
        self.sensor_stats = {}
        self.global_stats = 0
        self.schedule( 3600, self.decay )

    def deinit( self ):
        pass

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

        self.cli.onecmd( command )
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

            if task[ 0 ] not in self.allowed_commands:
                self.log( "ignoring command not allowed: %s" % str( task ) )
                continue
            if self.isQuotaAllowed( dest, task ):
                self.execTask( task, dest, expiry = expiry, invId = invId )

        return ( True, )