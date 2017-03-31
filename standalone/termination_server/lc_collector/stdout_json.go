// Copyright 2015 refractionPOINT
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lcCollector


import (
	"fmt"
	"sync"
	"encoding/json"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/lc_server"
)

type stdOutJSONCollector struct {
	connect <- chan lcServer.ConnectMessage
	disconnect <- chan lcServer.DisconnectMessage
	incoming <- chan lcServer.TelemetryMessage
	stop chan bool
	nHandlers int
	isHumanReadable bool
	ouputWG sync.WaitGroup
	mu sync.Mutex
}

func NewStdoutJSON(nHandlers int, isHumanReadable bool) Collector {
	c  := new(stdOutJSONCollector)
	c.nHandlers = nHandlers
	c.isHumanReadable = isHumanReadable
	c.stop = make(chan bool)
	return c
}

func (c *stdOutJSONCollector) SetChannels(connect <- chan lcServer.ConnectMessage, 
										  disconnect <- chan lcServer.DisconnectMessage, 
										  incoming <- chan lcServer.TelemetryMessage) {
	c.connect = connect
	c.disconnect = disconnect
	c.incoming = incoming
}
	
func (c *stdOutJSONCollector) Start() error {
	c.ouputWG.Add(c.nHandlers)
	for i := 0; i < c.nHandlers; i++ {
		go c.handler()
	}

	return nil
}

func (c *stdOutJSONCollector) Stop() {
	for i := 0; i < c.nHandlers; i++ {
		c.stop <- true
	}
	c.ouputWG.Wait()
}

func (c *stdOutJSONCollector) handler() {
	defer c.ouputWG.Done()

	for {
		var o string
		var isExit bool

		select {
		case <- c.stop:
			isExit = true
			break
		case msg := <- c.connect:
			o = fmt.Sprintf("CONNECT: %s (%s @ %s)", msg.AID, msg.Hostname, msg.InternalIP)
		case msg := <- c.disconnect:
			o = fmt.Sprintf("DISCONNECT: %s", msg.AID)
		case msg := <- c.incoming:
			wrapper := make(map[string]interface{}, 2)
			wrapper["event"] = msg.Event.ToJSON()
			wrapper["routing"] = make(map[string]interface{}, 1)
			wrapper["routing"].(map[string]interface{})["aid"] = msg.AID
			var JSONMessage []byte
			var err error
			if c.isHumanReadable {
				JSONMessage, err = json.MarshalIndent(wrapper, "", "    ")
			} else {
				JSONMessage, err = json.Marshal(wrapper)
			}

			if err != nil {
				o = fmt.Sprintf("ERROR: %s = %s", msg.AID, err)
			} else {
				o = string(JSONMessage)
			}
		}

		if isExit {
			break
		}

		c.mu.Lock()
		fmt.Println(o)
		c.mu.Unlock()
	}
}