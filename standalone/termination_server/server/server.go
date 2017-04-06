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

// Package server implements the core logic to "keep the lights on" for LimaCharlie clients.
// It takes care of enrollment and loading/unloading of the approproate modules. It does not
// implement any specific transport or output as these are modular.
package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/hcp"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/lc_server_config"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/rpcm"
	"io/ioutil"
	"net"
	"sync"
)

// ConnectMessage is a struct holding the information a Collector will get when a new client connects.
type ConnectMessage struct {
	// AID of the client that is connecting.
	AID *hcp.AgentID
	// Hostname of the client at the time the connection was established.
	Hostname string
	// Internal IP the client had at the time the connection was established.
	InternalIP net.IP
}

// DisconnectMessage is a struct holding the information a Collector will get when a client disconnects.
type DisconnectMessage struct {
	// AID of the client disconnecting.
	AID *hcp.AgentID
}

// TelemetryMessage is a struct holding a telemetry event from a sensor, the real payloads.
type TelemetryMessage struct {
	// Event payload from the client.
	Event *rpcm.Sequence
	// AID of the client sending the payload.
	AID *hcp.AgentID
}

// EnrollmentRule represents one pair of OrgID and InstallerID that are whitelisted to be enrolled.
type EnrollmentRule struct {
	OID uuid.UUID
	IID uuid.UUID
}

// ModuleRule represents a module to be loaded on all clients with an AgentID matching the mask.
type ModuleRule struct {
	// AID is a wildcarded AgentID that represents which clients this rule applies to.
	AID hcp.AgentID
	// ModuleID is the type of module represented (HBS, Kernel Acquisition etc).
	ModuleID uint8
	// ModuleFile is the path where the module is on disk.
	ModuleFile string
	// Hash of the module on disk.
	Hash []byte
}

// ProfileRule represents the profile that should be applied to clients with AgentID matching the mask.
type ProfileRule struct {
	// AID is a wildcarded AgentID that represents which client this rule applies to.
	AID hcp.AgentID
	// ProfileFile is the path where the profile is on disk.
	ProfileFile string
	// Hash of the profile on disk.
	Hash []byte
}

// Server interface represents a core LimaCharlie server and provides an API to modify its behavior dynamically.
type Server interface {
	// SentEnrollmentSecret sets the secret value used when generating the HMAC (Enrollment Token) given to clients.
	// to prove their legitimate enrollment.
	SetEnrollmentSecret(secret string) error
	// SetEnrollmentRules sets the list of rules to apply for enrollment.
	SetEnrollmentRules(rules []EnrollmentRule) error
	// EnrollmentRules gets the list of rules that currently apply for enrollment.
	EnrollmentRules() []EnrollmentRule
	// SetModuleRules sets the rules determine which modules are loaded on which client.
	SetModuleRules(rules []ModuleRule) error
	// ModuleRules gets the list of rules that currently apply to loading modules on clients.
	ModuleRules() []ModuleRule
	// SetProfileRules sets the rules specifying which client gets whichs profile.
	SetProfileRules(rules []ProfileRule) error
	// ProfileRules gets the list of rules that currently apply to specify profiles.
	ProfileRules() []ProfileRule
	// NewClient creates a new context for a client connecting to the server.
	NewClient(sendFunc func(moduleID uint8, messages []*rpcm.Sequence) error) (Client, error)
	// GetChannels retrieves the channels a collector can receive on for sythesized activity of the server.
	GetChannels() (connect chan ConnectMessage, disconnect chan DisconnectMessage, incoming chan TelemetryMessage)
	// Stop tells the server to start draining.
	Stop() error
	// Determines if the server is done draining.
	IsClosed() bool
}

type server struct {
	mu               sync.RWMutex
	enrollmentSecret string
	enrollmentRules  []EnrollmentRule
	moduleRules      []ModuleRule
	profileRules     []ProfileRule

	online map[hcp.AgentID]Client

	connectChan    chan ConnectMessage
	disconnectChan chan DisconnectMessage
	incomingChan   chan TelemetryMessage

	isClosing bool
}

// NewServer creates a new Server instance with the configurations specified in the protobuf.
func NewServer(config *lcServerConfig.Config) (Server, error) {
	var err error

	s := new(server)

	// List of rules that are currently active.
	s.enrollmentRules = make([]EnrollmentRule, 0)
	s.moduleRules = make([]ModuleRule, 0)
	s.profileRules = make([]ProfileRule, 0)

	// A map representing which clients are currently online and available.
	s.online = make(map[hcp.AgentID]Client)

	// Channels used to send the server activity and telemetry to Collectors.
	s.connectChan = make(chan ConnectMessage)
	s.disconnectChan = make(chan DisconnectMessage)
	s.incomingChan = make(chan TelemetryMessage)

	if config == nil {
		// If no config is provided we just return a blank server.
		return s, err
	}

	// Loading the rules from the proto into the internal format.
	for _, rule := range config.GetEnrollmentRules().GetRule() {
		r := EnrollmentRule{}

		if r.OID, err = uuid.Parse(rule.GetOid()); err != nil {
			return s, err
		}
		if r.IID, err = uuid.Parse(rule.GetIid()); err != nil {
			return s, err
		}
		s.enrollmentRules = append(s.enrollmentRules, r)
	}

	for _, rule := range config.GetModuleRules().GetRule() {
		r := ModuleRule{}

		r.ModuleID = uint8(rule.GetModuleId())

		if !r.AID.FromString(rule.GetAid()) {
			return s, fmt.Errorf("server: failed to parse AID: %s", rule.GetAid())
		}

		r.ModuleFile = rule.GetModuleFile()

		// We calculate the hash now and we'll use it to ensure the file
		// has not changed by the time we serve it to a client.
		fileContent, err := ioutil.ReadFile(r.ModuleFile)
		if err != nil {
			return s, err
		}

		hash := sha256.Sum256(fileContent)
		r.Hash = hash[:]

		s.moduleRules = append(s.moduleRules, r)
	}

	for _, rule := range config.GetProfileRules().GetRule() {
		r := ProfileRule{}

		if !r.AID.FromString(rule.GetAid()) {
			return s, fmt.Errorf("server: failed to parse AID: %s", rule.GetAid())
		}

		r.ProfileFile = rule.GetProfileFile()

		// We calculate the hash now and we'll use it to ensure the file
		// has not changed by the time we serve it to a client.
		fileContent, err := ioutil.ReadFile(r.ProfileFile)
		if err != nil {
			return s, err
		}

		hash := sha256.Sum256(fileContent)
		r.Hash = hash[:]

		s.profileRules = append(s.profileRules, r)
	}

	s.enrollmentSecret = config.GetSecretEnrollmentToken()

	return s, err
}

// SentEnrollmentSecret sets the secret value used when generating the HMAC (Enrollment Token) given to clients.
// to prove their legitimate enrollment.
func (srv *server) SetEnrollmentSecret(secret string) error {
	defer srv.mu.Unlock()
	srv.mu.Lock()
	srv.enrollmentSecret = secret
	return nil
}

// SetEnrollmentRules sets the list of rules to apply for enrollment.
func (srv *server) SetEnrollmentRules(rules []EnrollmentRule) error {
	defer srv.mu.Unlock()
	srv.mu.Lock()
	srv.enrollmentRules = rules
	return nil
}

// EnrollmentRules gets the list of rules that currently apply for enrollment.
func (srv *server) EnrollmentRules() []EnrollmentRule {
	defer srv.mu.RUnlock()
	srv.mu.RLock()
	r := make([]EnrollmentRule, len(srv.enrollmentRules))
	copy(r, srv.enrollmentRules)
	return r
}

// SetModuleRules sets the rules determine which modules are loaded on which client.
func (srv *server) SetModuleRules(rules []ModuleRule) error {
	defer srv.mu.Unlock()
	srv.mu.Lock()
	srv.moduleRules = rules
	return nil
}

// ModuleRules gets the list of rules that currently apply to loading modules on clients.
func (srv *server) ModuleRules() []ModuleRule {
	defer srv.mu.RUnlock()
	srv.mu.RLock()
	r := make([]ModuleRule, len(srv.moduleRules))
	copy(r, srv.moduleRules)
	return r
}

// SetProfileRules sets the rules specifying which client gets whichs profile.
func (srv *server) SetProfileRules(rules []ProfileRule) error {
	defer srv.mu.Unlock()
	srv.mu.Lock()
	srv.profileRules = rules
	return nil
}

// ProfileRules gets the list of rules that currently apply to specify profiles.
func (srv *server) ProfileRules() []ProfileRule {
	defer srv.mu.RUnlock()
	srv.mu.RLock()
	r := make([]ProfileRule, len(srv.profileRules))
	copy(r, srv.profileRules)
	return r
}

func (srv *server) validateEnrollmentToken(aid hcp.AgentID, token []byte) bool {
	defer srv.mu.RUnlock()
	srv.mu.RLock()

	hmacToken := hmac.New(sha256.New, []byte(srv.enrollmentSecret))
	hmacToken.Write([]byte(aid.String()))
	expectedToken := hmacToken.Sum(nil)

	return hmac.Equal(token, expectedToken)
}

func (srv *server) generateEnrollmentToken(aid hcp.AgentID) []byte {
	hmacToken := hmac.New(sha256.New, []byte(srv.enrollmentSecret))
	hmacToken.Write([]byte(aid.String()))

	return hmacToken.Sum(nil)
}

func (srv *server) isWhitelistedForEnrollment(oID uuid.UUID, iID uuid.UUID) bool {
	defer srv.mu.RUnlock()
	srv.mu.RLock()

	for _, rule := range srv.enrollmentRules {
		if rule.OID == oID && rule.IID == iID {
			return true
		}
	}

	return false
}

func (srv *server) enrollClient(c *client) ([]*rpcm.Sequence, error) {
	defer srv.mu.RUnlock()
	srv.mu.RLock()

	aID := c.AgentID()

	if !srv.isWhitelistedForEnrollment(aID.OID, aID.IID) {
		return nil, fmt.Errorf("server: org or installer not whitelisted: %s / %s", aID.OID, aID.IID)
	}

	aID.SID = uuid.New()
	c.aID = aID

	enrollmentToken := srv.generateEnrollmentToken(aID)

	// The message to the enrolling client specifies its new SID and the token proving legitimate enrollment.
	return []*rpcm.Sequence{rpcm.NewSequence().
		AddInt8(rpcm.RP_TAGS_OPERATION, hcp.CmdSetHCPID).
		AddSequence(rpcm.RP_TAGS_HCP_IDENT, c.aID.ToSequence()).
		AddBuffer(rpcm.RP_TAGS_HCP_ENROLLMENT_TOKEN, enrollmentToken)}, nil
}

// Get the list of modules the client should have loaded.
func (srv *server) getExpectedModulesFor(aID hcp.AgentID) []ModuleRule {
	defer srv.mu.RUnlock()
	srv.mu.RLock()

	var modules []ModuleRule
	for _, moduleInfo := range srv.moduleRules {
		if moduleInfo.AID.Matches(aID) {
			modules = append(modules, moduleInfo)
		}
	}

	return modules
}

// Get the first matching HBS profile for this sensor.
func (srv *server) getHBSProfileFor(aID hcp.AgentID) (ProfileRule, bool) {
	defer srv.mu.RUnlock()
	srv.mu.RLock()

	for _, profile := range srv.profileRules {
		if profile.AID.Matches(aID) {
			return profile, true
		}
	}

	return ProfileRule{}, false
}

// GetChannels retrieves the channels a collector can receive on for sythesized activity of the server.
func (srv *server) GetChannels() (connect chan ConnectMessage, disconnect chan DisconnectMessage, incoming chan TelemetryMessage) {
	defer srv.mu.Unlock()
	srv.mu.Lock()

	return srv.connectChan, srv.disconnectChan, srv.incomingChan
}

// NewClient creates a new context for a client connecting to the server.
func (srv *server) NewClient(sendFunc func(moduleID uint8, messages []*rpcm.Sequence) error) (Client, error) {
	defer srv.mu.RUnlock()
	srv.mu.RLock()

	if srv.isClosing {
		return nil, errors.New("server: closing")
	}

	c := new(client)
	c.srv = srv
	c.sendCB = sendFunc
	c.isOnline = true

	// The client is not added immediately to the list of online clients since
	// this will be done by the client itself once it has authenticated.

	return c, nil
}

// Stop tells the server to start draining.
func (srv *server) Stop() error {
	defer srv.mu.Unlock()
	srv.mu.Lock()

	srv.isClosing = true
	return nil
}

// Determines if the server is done draining.
func (srv *server) IsClosed() bool {
	defer srv.mu.RUnlock()
	srv.mu.RLock()

	if srv.isClosing && 0 == len(srv.online) {
		return true
	}

	return false
}

func (srv *server) setOnline(c *client, msg ConnectMessage) error {
	defer srv.mu.Unlock()
	srv.mu.Lock()

	if !srv.isClosing {
		srv.connectChan <- msg
		srv.online[c.aID] = c
		return nil
	}

	return errors.New("server: closing")
}

func (srv *server) setOffline(c *client) {
	defer srv.mu.Unlock()
	srv.mu.Lock()
	delete(srv.online, c.aID)
}
