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
ObjectTypes = Actor.importLib( '../../ObjectsDb', 'ObjectTypes' )
StatefulActor = Actor.importLib( '../../Detects', 'StatefulActor' )

class SensorIssues ( StatefulActor ):
    def initMachines( self, parameters ):
        self.shardingKey = 'agentid'
        self.machines = {
            'sensor_spawning_processes' :
'''
SAMProcessDescendants( parameters = { 'is_direct_only' : True } )
    .feed_parents( SAMSelector( parameters = {
        'event/notification.NEW_PROCESS/base.FILE_PATH' : r'.*(/|\\\)hcp(\.exe)?' } ) )
    .feed_descendants( SAMSelector( parameters = {
        'event/notification.NEW_PROCESS' : None } ) )
''',

            'sensor_restarting' :
'''
SAMTimeBurst( parameters = { 'within' : 60, 'min_burst' : 3 } )
    .feed_from( SAMSelector( parameters = {
        'event/notification.STARTING_UP' : None } ) )
'''
        }

    def processDetects( self, detects ):
        return detects