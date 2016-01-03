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
import hashlib
from sets import Set
import time
SAMLoadWidgets = Actor.importLib( 'analytics/StateAnalysis', 'SAMLoadWidgets' )

def GenerateDetectReport( agentid, msgIds, cat, detect ):
    if type( msgIds ) is not tuple and type( msgIds ) is not list:
        msgIds = ( msgIds, )
    if type( agentid ) is tuple or type( agentid ) is list:
        agentid = ' / '.join( agentid )
    reportId = hashlib.sha256( str( msgIds ) ).hexdigest()
    return { 'source' : agentid, 'msg_ids' : msgIds, 'cat' : cat, 'detect' : detect, 'report_id' : reportId }

class StatelessActor ( Actor ):
    def init( self, parameters ):
        if not hasattr( self, 'process' ):
            raise Exception( 'Stateless Actor has no "process" function' )
        self._reporting = self.getActorHandle( 'analytics/report' )
        self._tasking = None
        self.handle( 'process', self._process )

    def task( self, dest, cmdsAndArgs, expiry = None, inv_id = None ):
        if self._tasking is None:
            self._tasking = self.getActorHandle( 'analytics/autotasking', mode = 'affinity' )
            self.log( "creating tasking handle for the first time for this detection module" )

        if type( cmdsAndArgs[ 0 ] ) not in ( tuple, list ):
            cmdsAndArgs = ( cmdsAndArgs, )
        data = { 'dest' : dest, 'tasks' : cmdsAndArgs }

        if expiry is not None:
            data[ 'expiry' ] = expiry
        if inv_id is not None:
            data[ 'inv_id' ] = inv_id

        self._tasking.shoot( 'task', data, key = dest )
        self.log( "sent for tasking: %s" % ( str(cmdsAndArgs), ) )

    def _process( self, msg ):
        detects = self.process( msg )

        if 0 != len( detects ):
            self.log( "reporting detects generated" )
            routing, event, mtd = msg.data
            cat = type( self ).__name__
            cat = cat[ cat.rfind( '.' ) + 1 : ]
            for detect, taskings in detects:
                report = GenerateDetectReport( routing[ 'agentid' ],
                                               ( routing[ 'event_id' ], ),
                                               cat,
                                               detect )
                self._reporting.shoot( 'report', report )
                if taskings is not None and 0 != len( taskings ):
                    self.task( routing[ 'agentid' ], taskings, expiry = ( 60 * 60 ), inv_id = report[ 'report_id' ] )
        return ( True, )

class StatefulActor ( Actor ):
    def init( self, parameters ):
        self._compiled_machines = {}
        self._machine_activity = {}
        self._machine_ttl = parameters.get( 'machine_ttl', ( 60 * 60 * 24 * 7 ) )
        if not hasattr( self, 'initMachines' ):
            raise Exception( 'Stateful Actor has no "initMachines" function' )
        if not hasattr( self, 'processDetects' ):
            raise Exception( 'Stateful Actor has no "processDetects" function' )

        self.initMachines( parameters )

        if not hasattr( self, 'machines' ):
            raise Exception( 'Stateful Actor has no associated detection machines' )
        if not hasattr( self, 'shardingKey' ):
            raise Exception( 'Stateful Actor has no associated shardingKey (or None)' )

        self._reporting = self.getActorHandle( 'analytics/report' )
        self.handle( 'process', self._process )

        self.schedule( 60 * 60, self._garbageCollectOldMachines )

    def _garbageCollectOldMachines( self ):
        for shard in self._machine_activity.keys():
            if self._machine_activity[ shard ] < time.time() - self._machine_ttl:
                del( self._machine_activity[ shard ] )
                del( self._compiled_machines[ shard ] )

    def task( self, dest, cmdsAndArgs, expiry = None, inv_id = None ):
        if self._tasking is None:
            self._tasking = self.getActorHandle( 'analytics/autotasking', mode = 'affinity' )
            self.log( "creating tasking handle for the first time for this detection module" )

        if type( cmdsAndArgs[ 0 ] ) not in ( tuple, list ):
            cmdsAndArgs = ( cmdsAndArgs, )
        data = { 'dest' : dest, 'tasks' : cmdsAndArgs }

        if expiry is not None:
            data[ 'expiry' ] = expiry
        if inv_id is not None:
            data[ 'inv_id' ] = inv_id

        self._tasking.shoot( 'task', data, key = dest )
        self.log( "sent for tasking: %s" % ( str(cmdsAndArgs), ) )

    def _process( self, msg ):
        routing, event, mtd = msg.data

        shard = None
        if self.shardingKey is not None:
            shard = routing.get( self.shardingKey, None )

        if shard not in self._compiled_machines:
            self.log( 'creating new state machine' )
            self._compiled_machines[ shard ] = {}
            for mName, m in self.machines.iteritems():
                self._compiled_machines[ shard ][ mName ] = eval( '(%s)' % m, SAMLoadWidgets(), { 'self' : self } )

        actual_machines = self._compiled_machines[ shard ]
        self._machine_activity[ shard ] = time.time()

        machineEvent = { 'event' : event, 'routing' : routing }

        for mName, m in actual_machines.iteritems():
            detects = m._execute( machineEvent )
            if detects is not None and 0 != len( detects ):
                detects = self.processDetects( detects )
                for detect in detects:
                    self._reporting.shoot( 'report',
                                           GenerateDetectReport( tuple( Set( [ e[ 'routing' ][ 'agentid' ] for e in detect ] ) ),
                                                                 tuple( Set( [ e[ 'routing' ][ 'event_id' ] for e in detect ] ) ),
                                                                 '%s/%s' % ( self.__class__.__name__, mName ),
                                                                 detect ) )
        return ( True, )