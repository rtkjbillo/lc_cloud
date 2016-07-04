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
ProcessDescendant = Actor.importLib( '../../analytics/StateAnalysis/descriptors', 'ProcessDescendant' )
EventBurst = Actor.importLib( '../../analytics/StateAnalysis/descriptors', 'EventBurst' )
StatefulActor = Actor.importLib( '../../Detects', 'StatefulActor' )

class SensorIssues ( StatefulActor ):
    def initMachines( self, parameters ):
        self.shardingKey = 'agentid'

        #TODO: vary the logic for other platforms and ensure it's the right executable name.
        hcpProcesses = r'.*(/|\\)((rphcp)|(hcp_.+))\.exe'
        anyApps = r'.*'
        
        hcpSpawningProcesses = ProcessDescendant( name = 'hcp_spawns_anything',
                                                  priority = 99,
                                                  summary = 'LimaCharlie was observed spawning processes',
                                                  parentRegExp = hcpProcesses,
                                                  childRegExp = anyApps,
                                                  isDirectOnly = True )

        hcpFrequentRestart = EventBurst( name = 'hcp_frequent_restart',
                                         priority = 50,
                                         summary = 'LimaCharlie sensor restarts frequently',
                                         eventType = 'notification.STARTING_UP',
                                         nPerBurst = 3,
                                         withinMilliSeconds = 60 * 1000 )

        self.addStateMachineDescriptor( hcpSpawningProcesses )
        self.addStateMachineDescriptor( hcpFrequentRestart )