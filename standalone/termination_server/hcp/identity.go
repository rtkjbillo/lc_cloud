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

/*
Package hcp contains definitions and helpers specific to the operation of the
LimaCharlie Host Common Platform.
*/
package hcp

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/rpcm"
	"strconv"
	"strings"
)

// WildcardUUID is the value used to indicate a wildcard for org, installer or sensor ID of AgentID.
var WildcardUUID uuid.UUID

// Wildcard values for platform and architecture of AgentID.
const (
	WildcardPlatform     = 0
	WildcardArchitecture = 0
)

// Module IDs of common HCP modules.
const (
	ModuleIDHCP       = 1
	ModuleIDHBS       = 2
	ModuleIDKernelAcq = 5
)

// Command IDs of HCP commands.
const (
	CmdLoadModule    = 1
	CmdUnloadModule  = 2
	CmdSetHCPID      = 3
	CmdSetGlobalTime = 4
	CmdQuit          = 5
	CmdUpgrade       = 6
	CmdSetHCPConf    = 7
	CmdDisconnect    = 8
)

const (
	numComponentsInAgentID = 5
	agentIDWildcardValue   = "0"
)

// AgentID is the logical representation of the ID components used
// to identify a specific sensor and its basic characteristics.
type AgentID struct {
	OID          uuid.UUID
	IID          uuid.UUID
	SID          uuid.UUID
	Platform     uint32
	Architecture uint32
}

// IsAbsolute returns true if none of the components of the AgentID are wildcards (0).
func (aid AgentID) IsAbsolute() bool {
	if aid.OID == WildcardUUID ||
		aid.IID == WildcardUUID ||
		aid.Platform == WildcardPlatform ||
		aid.Architecture == WildcardArchitecture {
		return false
	}
	return true
}

// IsSIDWild returns true if the SensorId component of the AgentID is a wildcard.
func (aid AgentID) IsSIDWild() bool {
	return aid.SID == WildcardUUID
}

func uuidAsWildString(id uuid.UUID) string {
	if id == WildcardUUID {
		return "0"
	}
	return id.String()
}

// String converts the AgentID to its standardized string representation.
func (aid AgentID) String() string {

	return fmt.Sprintf("%s.%s.%s.%x.%x",
		uuidAsWildString(aid.OID),
		uuidAsWildString(aid.IID),
		uuidAsWildString(aid.SID),
		aid.Platform,
		aid.Architecture)
}

// FromString converts the standardized string representation of an AgentID into an AgentID.
func (aid *AgentID) FromString(s string) error {
	var (
		err   error
		tmp64 uint64
	)
	components := strings.Split(s, ".")
	if len(components) != numComponentsInAgentID {
		return errors.New("AgentID: invalid number of components in string")
	}

	if components[0] == agentIDWildcardValue {
		aid.OID = WildcardUUID
	} else if aid.OID, err = uuid.Parse(components[0]); err != nil {
		return err
	}

	if components[1] == agentIDWildcardValue {
		aid.IID = WildcardUUID
	} else if aid.IID, err = uuid.Parse(components[1]); err != nil {
		return err
	}

	if components[2] == agentIDWildcardValue {
		aid.SID = WildcardUUID
	} else if aid.SID, err = uuid.Parse(components[2]); err != nil {
		return err
	}

	if tmp64, err = strconv.ParseUint(components[3], 16, 32); err != nil {
		return err
	}
	aid.Platform = uint32(tmp64)

	if tmp64, err = strconv.ParseUint(components[4], 16, 32); err != nil {
		return err
	}
	aid.Architecture = uint32(tmp64)

	return nil
}

// Matches returns true if both AgentIDs are equal (or wildcarded) in all components.
func (aid AgentID) Matches(compareTo AgentID) bool {
	if aid.OID != WildcardUUID && compareTo.OID != WildcardUUID && aid.OID != compareTo.OID {
		return false
	}

	if aid.IID != WildcardUUID && compareTo.IID != WildcardUUID && aid.IID != compareTo.IID {
		return false
	}

	if aid.SID != WildcardUUID && compareTo.SID != WildcardUUID && aid.SID != compareTo.SID {
		return false
	}

	if aid.Platform != WildcardPlatform && compareTo.Platform != WildcardPlatform && aid.Platform != compareTo.Platform {
		return false
	}

	if aid.Architecture != WildcardArchitecture && compareTo.Architecture != WildcardArchitecture && aid.Architecture != compareTo.Architecture {
		return false
	}

	return true
}

// FromSequence loads an AgentID from an rpcm Sequence in the standard format.
func (aid *AgentID) FromSequence(message *rpcm.Sequence) error {
	var (
		buf []byte
		ok  bool
	)
	if buf, ok = message.GetBuffer(rpcm.RP_TAGS_HCP_ORG_ID); !ok || len(aid.OID) != len(buf) {
		return errors.New("hcp: invalid oid")
	}
	copy(aid.OID[:], buf)

	if buf, ok = message.GetBuffer(rpcm.RP_TAGS_HCP_INSTALLER_ID); !ok || len(aid.IID) != len(buf) {
		return errors.New("hcp: invalid iid")
	}
	copy(aid.IID[:], buf)

	if buf, ok = message.GetBuffer(rpcm.RP_TAGS_HCP_SENSOR_ID); !ok || len(aid.SID) != len(buf) {
		return errors.New("hcp: invalid sid")
	}
	copy(aid.SID[:], buf)

	if aid.Architecture, ok = message.GetInt32(rpcm.RP_TAGS_HCP_ARCHITECTURE); !ok {
		return errors.New("hcp: missing architecture")
	}

	if aid.Platform, ok = message.GetInt32(rpcm.RP_TAGS_HCP_PLATFORM); !ok {
		return errors.New("hcp: missing platform")
	}

	return nil
}

// ToSequence stores the AgentID in the standard rpcm Sequence format.
func (aid AgentID) ToSequence() *rpcm.Sequence {
	seq := rpcm.NewSequence().
		AddBuffer(rpcm.RP_TAGS_HCP_ORG_ID, aid.OID[:]).
		AddBuffer(rpcm.RP_TAGS_HCP_INSTALLER_ID, aid.IID[:]).
		AddBuffer(rpcm.RP_TAGS_HCP_SENSOR_ID, aid.SID[:]).
		AddInt32(rpcm.RP_TAGS_HCP_ARCHITECTURE, aid.Platform).
		AddInt32(rpcm.RP_TAGS_HCP_PLATFORM, aid.Architecture)

	return seq
}
