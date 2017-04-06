// Copyright 2017 Google, Inc
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

package collector

import (
	"encoding/json"
	"fmt"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/server"
	"sync"
)

type stdOutJSONCollector struct {
	connect       <-chan server.ConnectMessage
	disconnect    <-chan server.DisconnectMessage
	incoming      <-chan server.TelemetryMessage
	stop          chan bool
	numHandlers   int
	isPrettyPrint bool
	ouputWG       sync.WaitGroup
	mu            sync.Mutex
}

// NewStdoutJSON creates a new collector that will output the events to the stdout as JSON.
// numHandlers specifies the number of Go Routines handling output while isPrettyPrint will
// pretty print the JSON.
func NewStdoutJSON(numHandlers int, isPrettyPrint bool) Collector {
	return &stdOutJSONCollector{numHandlers: numHandlers, isPrettyPrint: isPrettyPrint, stop: make(chan bool, numHandlers)}
}

// Set the channels used to collect output.
func (s *stdOutJSONCollector) SetChannels(connect <-chan server.ConnectMessage, disconnect <-chan server.DisconnectMessage,
	incoming <-chan server.TelemetryMessage) {
	s.connect = connect
	s.disconnect = disconnect
	s.incoming = incoming
}

// Start the collector and begin outputting. This will launch numHandlers GoRoutines (as specified in factory).
// Caller is responsible for calling Stop() for cleanup.
func (s *stdOutJSONCollector) Start() error {
	s.ouputWG.Add(s.numHandlers)
	for i := 0; i < s.numHandlers; i++ {
		go s.handler()
	}

	return nil
}

// Stop the collector and output. This will shutdown the collector's handlers, blocking until they are stopped.
func (s *stdOutJSONCollector) Stop() {
	for i := 0; i < s.numHandlers; i++ {
		s.stop <- true
	}
	s.ouputWG.Wait()
}

func (s *stdOutJSONCollector) handler() {
	defer s.ouputWG.Done()

	for {
		var o string

		select {
		case <-s.stop:
			return
		case msg := <-s.connect:
			o = fmt.Sprintf("CONNECT: %s (%s @ %s)", msg.AID, msg.Hostname, msg.InternalIP)
		case msg := <-s.disconnect:
			o = fmt.Sprintf("DISCONNECT: %s", msg.AID)
		case msg := <-s.incoming:
			wrapper := make(map[string]interface{}, 2)
			wrapper["event"] = msg.Event.ToJSON()
			wrapper["routing"] = make(map[string]interface{}, 1)
			wrapper["routing"].(map[string]interface{})["aid"] = msg.AID
			if s.isPrettyPrint {
				if JSONMessage, err := json.MarshalIndent(wrapper, "", "    "); err != nil {
					o = fmt.Sprintf("ERROR: %s = %s", msg.AID, err)
				} else {
					o = string(JSONMessage)
				}
			} else {
				if JSONMessage, err := json.Marshal(wrapper); err != nil {
					o = fmt.Sprintf("ERROR: %s = %s", msg.AID, err)
				} else {
					o = string(JSONMessage)
				}
			}
		}

		go func() {
			s.mu.Lock()
			fmt.Println(o)
			s.mu.Unlock()
		}()
	}
}
