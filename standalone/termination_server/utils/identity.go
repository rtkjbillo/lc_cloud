package hcp

import (
	"github.com/google/uuid"
	"fmt"
)

const (
	MODULE_ID_HCP = 1
	MODULE_ID_HBS = 2
	MODULE_ID_KERNEL_ACQ = 5
)

type AgentId struct {
	Oid uuid.UUID
	Iid uuid.UUID
	Sid uuid.UUID
	Platform uint32
	Architecture uint32
}

func (this AgentId)IsAbsolute() bool {
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

func (this AgentId)IsSidWild() bool {
	var emptyUuid uuid.UUID
	return this.Sid == emptyUuid
}

func UuidAsWildString(id uuid.UUID) string {
	var emptyUuid uuid.UUID
	if id == emptyUuid {
		return "0"
	} else {
		return id.String()
	}
}

func (this AgentId)ToString() string {
	
	return fmt.Sprintf("%s.%s.%s.%x.%x", 
					   UuidAsWildString(this.Oid),
					   UuidAsWildString(this.Iid),
					   UuidAsWildString(this.Sid),
					   this.Platform,
					   this.Architecture)
}
