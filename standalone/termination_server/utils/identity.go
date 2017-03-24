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

/*
The HCP package contains definitions and helpers specific to the operation of the 
LimaCharlie Host Common Platform.
*/
package hcp

import (
	"fmt"
	"github.com/google/uuid"
	"strconv"
	"strings"
)

// Module IDs of common HCP modules
const (
	MODULE_ID_HCP        = 1
	MODULE_ID_HBS        = 2
	MODULE_ID_KERNEL_ACQ = 5
)

// Command IDs of HCP commands
const (
	LOAD_MODULE     = 1
	UNLOAD_MODULE   = 2
	SET_HCP_ID      = 3
	SET_GLOBAL_TIME = 4
	QUIT            = 5
)

// AgentId is the logical representation of the ID components used
// to identify a specific sensor and its basic characteristics
type AgentId struct {
	Oid          uuid.UUID
	Iid          uuid.UUID
	Sid          uuid.UUID
	Platform     uint32
	Architecture uint32
}

// IsAbsolute returns true if none of the components of the AgentId are wildcards (0)
func (this AgentId) IsAbsolute() bool {
	var emptyUuid uuid.UUID
	if this.Oid == emptyUuid ||
		this.Iid == emptyUuid ||
		this.Platform == 0 ||
		this.Architecture == 0 {
		return false
	} else {
		return true
	}
}

// IsSidWild returns true if the SensorId component of the AgentId is a wildcard
func (this AgentId) IsSidWild() bool {
	var emptyUuid uuid.UUID
	return this.Sid == emptyUuid
}

func uuidAsWildString(id uuid.UUID) string {
	var emptyUuid uuid.UUID
	if id == emptyUuid {
		return "0"
	} else {
		return id.String()
	}
}

// ToString converts the AgentId to its standardized string representation
func (this AgentId) ToString() string {

	return fmt.Sprintf("%s.%s.%s.%x.%x",
		uuidAsWildString(this.Oid),
		uuidAsWildString(this.Iid),
		uuidAsWildString(this.Sid),
		this.Platform,
		this.Architecture)
}

// FromString converts the standardized string representation of an AgentId into an AgentId
func (this AgentId) FromString(s string) bool {
	var err error
	var emptyUuid uuid.UUID
	var tmp64 uint64
	components := strings.Split(s, ".")
	if len(components) != 5 {
		return false
	}

	if components[0] == "0" {
		this.Oid = emptyUuid
	} else if this.Oid, err = uuid.Parse(components[0]); err != nil {
		return false
	}

	if components[1] == "0" {
		this.Iid = emptyUuid
	} else if this.Iid, err = uuid.Parse(components[1]); err != nil {
		return false
	}

	if components[2] == "0" {
		this.Sid = emptyUuid
	} else if this.Sid, err = uuid.Parse(components[2]); err != nil {
		return false
	}

	if tmp64, err = strconv.ParseUint(components[3], 16, 32); err != nil {
		return false
	}
	this.Platform = uint32(tmp64)

	if tmp64, err = strconv.ParseUint(components[3], 16, 32); err != nil {
		return false
	}
	this.Architecture = uint32(tmp64)

	return true
}

// Matches returns true if both AgentIds are equal (or wildcarded) in all components
func (this AgentId) Matches(compareTo AgentId) bool {
	var emptyUuid uuid.UUID
	if (this.Oid == emptyUuid || compareTo.Oid == emptyUuid || this.Oid == compareTo.Oid) &&
		(this.Iid == emptyUuid || compareTo.Iid == emptyUuid || this.Iid == compareTo.Iid) &&
		(this.Sid == emptyUuid || compareTo.Sid == emptyUuid || this.Sid == compareTo.Sid) &&
		(this.Platform == 0 || compareTo.Platform == 0 || this.Platform == compareTo.Platform) &&
		(this.Architecture == 0 || compareTo.Architecture == 0 || this.Architecture == compareTo.Architecture) {
		return true
	}

	return false
}
