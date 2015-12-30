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

class MacReconTools ( StatefulActor ):
    def initMachines( self, parameters ):
        self.shardingKey = 'agentid'
        self.machines = {
            'sensor_restarting' :
'''
SAMTimeBurst( parameters = { 'within' : 10, 'min_burst' : 4 } )
    .feed_from( SAMSelector( parameters = {
        'event/notification.NEW_PROCESS/base.FILE_PATH' : r'.*/((ifconfig)|(arp)|(route)|(ping)|(traceroute)|(nslookup)|(netstat)|(wget)|(curl))' } ) )
'''
        }

    def processDetects( self, detects ):
        return detects