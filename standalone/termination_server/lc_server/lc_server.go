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

package lcServer


import (
	"errors"
	"fmt"
	"net"
	"sync"
	"crypto/sha256"
	"crypto/hmac"
	"github.com/google/uuid"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/lc_server_config"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/rpcm"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/utils"
	"io/ioutil"
)

type ConnectMessage struct {
	AID *hcp.AgentID
	Hostname string
	InternalIP net.IP
}

type DisconnectMessage struct {
	AID *hcp.AgentID
}

type TelemetryMessage struct {
	Event *rpcm.Sequence
	AID *hcp.AgentID
}

type EnrollmentRule struct {
	OID uuid.UUID
	IID uuid.UUID
}

type ModuleRule struct {
	AID hcp.AgentID
	ModuleID uint8
	ModuleFile string
	Hash []byte
}

type ProfileRule struct {
	AID hcp.AgentID
	ProfileFile string
	Hash []byte
}

type Server interface {
	SetEnrollmentSecret(secret string) error
	SetEnrollmentRules(rules []EnrollmentRule) error
	EnrollmentRules() []EnrollmentRule
	SetModuleRules(rules []ModuleRule) error
	ModuleRules() []ModuleRule
	SetProfileRules(rules []ProfileRule) error
	ProfileRules() []ProfileRule
	NewClient(sendFunc func(moduleID uint8, messages []*rpcm.Sequence) error) (Client, error)
	GetChannels() (connect chan ConnectMessage, disconnect chan DisconnectMessage, incoming chan TelemetryMessage)
	Stop() error
	IsClosed() bool
}

type server struct {
	mu sync.RWMutex
	enrollmentSecret string
	enrollmentRules []EnrollmentRule
	moduleRules []ModuleRule
	profileRules []ProfileRule

	online map[hcp.AgentID]Client

	connectChannel chan ConnectMessage
	disconnectChannel chan DisconnectMessage
	incomingChannel chan TelemetryMessage

	isClosing bool
}

func NewServer(config *lcServerConfig.Config) (Server, error) {
	var err error
	
	s := new(server)

	s.enrollmentRules = make([]EnrollmentRule, 0)
	s.moduleRules = make([]ModuleRule, 0)
	s.profileRules = make([]ProfileRule, 0)
	s.online = make(map[hcp.AgentID]Client)

	s.connectChannel = make(chan ConnectMessage)
	s.disconnectChannel = make(chan DisconnectMessage)
	s.incomingChannel = make(chan TelemetryMessage)

	if config == nil {
		// If no config is provided we just return a blank server
		return s, err
	}

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
			return s, errors.New(fmt.Sprintf("failed to parse AID: %s", rule.GetAid()))
		}

		r.ModuleFile = rule.GetModuleFile()

		if fileContent, err := ioutil.ReadFile(r.ModuleFile); err == nil {
			hash := sha256.Sum256(fileContent)
			r.Hash = hash[:]
		} else  {
			return s, err
		}

		s.moduleRules = append(s.moduleRules, r)
	}

	for _, rule := range config.GetProfileRules().GetRule() {
		r := ProfileRule{}

		if !r.AID.FromString(rule.GetAid()) {
			return s, errors.New(fmt.Sprintf("failed to parse AID: %s", rule.GetAid()))
		}

		r.ProfileFile = rule.GetProfileFile()

		if fileContent, err := ioutil.ReadFile(r.ProfileFile); err == nil {
			hash := sha256.Sum256(fileContent)
			r.Hash = hash[:]
		} else  {
			return s, err
		}

		s.profileRules = append(s.profileRules, r)
	}

	s.enrollmentSecret = config.GetSecretEnrollmentToken()

	return s, err
}

func (srv *server) SetEnrollmentSecret(secret string) error {
	defer srv.mu.Unlock()
	srv.mu.Lock()
	srv.enrollmentSecret = secret
	return nil
}

func (srv *server) SetEnrollmentRules(rules []EnrollmentRule) error {
	defer srv.mu.Unlock()
	srv.mu.Lock()
	srv.enrollmentRules = rules
	return nil
}

func (srv *server) EnrollmentRules() []EnrollmentRule {
	defer srv.mu.RUnlock()
	srv.mu.RLock()
	r := make([]EnrollmentRule, len(srv.enrollmentRules))
	copy(r, srv.enrollmentRules)
	return r
}

func (srv *server) SetModuleRules(rules []ModuleRule) error {
	defer srv.mu.Unlock()
	srv.mu.Lock()
	srv.moduleRules = rules
	return nil
}

func (srv *server) ModuleRules() []ModuleRule {
	defer srv.mu.RUnlock()
	srv.mu.RLock()
	r := make([]ModuleRule, len(srv.moduleRules))
	copy(r, srv.moduleRules)
	return r
}

func (srv *server) SetProfileRules(rules []ProfileRule) error {
	defer srv.mu.Unlock()
	srv.mu.Lock()
	srv.profileRules = rules
	return nil
}

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
		return nil, errors.New(fmt.Sprintf("org or installer not whitelisted: %s / %s", aID.OID, aID.IID))
	}

	aID.SID = uuid.New()
	c.setAgentID(aID)

	enrollmentToken := srv.generateEnrollmentToken(aID)

	return []*rpcm.Sequence{rpcm.NewSequence().
			AddInt8(rpcm.RP_TAGS_OPERATION, hcp.SET_HCP_ID).
			AddSequence(rpcm.RP_TAGS_HCP_IDENT, c.aID.ToSequence()).
			AddBuffer(rpcm.RP_TAGS_HCP_ENROLLMENT_TOKEN, enrollmentToken)}, nil
}

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

func (srv *server) getHBSProfileFor(aID hcp.AgentID) (ProfileRule , bool) {
	defer srv.mu.RUnlock()
	srv.mu.RLock()

	for _, profile := range srv.profileRules {
		if profile.AID.Matches(aID) {
			return profile, true
		}
	}

	return ProfileRule{}, false
}

func (srv *server) GetChannels() (connect chan ConnectMessage, disconnect chan DisconnectMessage, incoming chan TelemetryMessage) {
	defer srv.mu.Unlock()
	srv.mu.Lock()

	return srv.connectChannel, srv.disconnectChannel, srv.incomingChannel
}

func (srv *server) NewClient(sendFunc func(moduleID uint8, messages []*rpcm.Sequence) error) (Client, error) {
	defer srv.mu.RUnlock()
	srv.mu.RLock()

	if srv.isClosing {
		return nil, errors.New("server closing")
	}

	c := new(client)
	c.srv = srv
	c.sendCB = sendFunc
	c.isOnline = true

	// The client is not added immediately to the list of online clients since
	// this will be done by the client itself once it has authenticated.

	return c, nil
}

func (srv *server) Stop() error {
	defer srv.mu.Unlock()
	srv.mu.Lock()

	srv.isClosing = true
	return nil
}

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
		srv.connectChannel <- msg
		srv.online[c.aID] = c
		return nil
	}

	return errors.New("server closing")
}

func (srv *server) setOffline(c *client) {
	defer srv.mu.Unlock()
	srv.mu.Lock()
	delete(srv.online, c.aID)
}