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
	"bytes"
	"fmt"
	"sync"
	"crypto/sha256"
	"github.com/google/uuid"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/lc_server_config"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/rpcm"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/utils"
)

const (
	WildcardUUID 
)

type SensorMessage struct {
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

type Client interface {
	Receive(moduleID uint8, messages []*rpcm.Sequence) error
	AgentID() hcp.AgentID
	Close()
}

type Server interface {
	SetEnrollmentSecret(secret string) error
	IsDebug() bool
	SetDebug(enabled bool)
	SetEnrollmentRules(rules []EnrollmentRule) error
	EnrollmentRules() []EnrollmentRule
	SetModuleRules(rules []ModuleRule) error
	ModuleRules() []ModuleRule
	SetProfileRules(rules []ProfileRule) error
	ProfileRules() []ProfileRule
	NewClient(sendFunc func(moduleID uint8, messages []*rpcm.Sequence) error) Client
	GetChannels() connect chan hcp.AgentID, disconnect chan hcp.AgentID, incoming chan SensorMessage
}

type server struct {
	mu sync.RWMutex
	enrollmentSecret string
	isDebug bool
	enrollmentRules []EnrollmentRule
	moduleRules []ModuleRule
	profileRules []ProfileRule

	online map[hcp.AgentID]Client

	connectChannel chan hcp.AgentID
	disconnectChannel chan hcp.AgentID
	incomingChannel chan *rpcm.Sequence
}

func NewServer() Server {
	s = new(server)

	s.enrollmentRules = make([]EnrollmentRule, 0)
	s.moduleRules = make([]ModuleRule, 0)
	s.ProfileRules = make([]ProfileRule, 0)

	return s
}

func NewServer(config *lcServerConfig.Config) Server {
	var err error
	s = NewServer().(server)

	s.online = make(map[hcp.AgentID]Client)

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

		r.ModuleID = rule.GetModuleId()

		if !r.AID.FromString(rule.GetAid()) {
			return s, errors.New(fmt.Sprintf("failed to parse AID: %s", rule.GetAid()))
		}

		r.ModuleFile = rule.GetModuleFile()

		if fileContent, err := ioutil.ReadFile(r.ModulePath); err == nil {
			r.Hash = sha256.Sum256(fileContent)
		} else  {
			return s, err
		}

		s.moduleRules = append(s.moduleRules, r)
	}

	for _, rule := range tmpConfig.GetProfileRules().GetRule() {
		r := ProfileRule{}

		if !r.AID.FromString(rule.GetAid()) {
			return s, errors.New(fmt.Sprintf("failed to parse AID: %s", rule.GetAid()))
		}

		r.ProfileFile = rule.GetModuleFile()

		if fileContent, err := ioutil.ReadFile(r.ProfileFile); err == nil {
			r.Hash = sha256.Sum256(fileContent)
		} else  {
			return s, err
		}

		s.profileRules = append(s.profileRules, r)
	}

	srv.connectChannel = make(chan hcp.AgentID)
	srv.disconnectChannel = make(chan hcp.AgentID)
	srv.incomingChannel = make(chan SensorMessage)

	return s, err
}

func (srv *server) SetEnrollmentSecret(secret string) error {
	defer srv.my.Unlock()
	srv.mu.Lock()
	srv.enrollmentSecret = secret
	return nil
}

func (srv *server) IsDebug() bool {
	defer srv.my.Unlock()
	srv.mu.Lock()
	return srv.isDebug
}

func (srv *server) SetDebug(enabled bool) {
	defer srv.my.Unlock()
	srv.mu.Lock()
	srv.isDebug = enabled
}

func (srv *server) SetEnrollmentRules(rules []EnrollmentRule) error {
	defer srv.my.Unlock()
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
	defer srv.my.Unlock
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
	copy(r, stv.profileRules)
	return r
}

func (srv *server) validateEnrollmentToken(aid hcp.AgentId, token []byte) bool {
	defer srv.mu.RUnlock()
	srv.mu.RLock()

	hmacToken := hmac.New(sha256.New, []byte(srv.enrollmentSecret))
	hmacToken.Write([]byte(aid.ToString()))
	expectedToken := hmacToken.Sum(nil)

	return hmac.Equal(token, expectedToken)
}

func (srv *server) generateEnrollmentToken(aid hcp.AgentId) []byte {
	defer srv.mu.RUnlock()
	srv.mu.RLock()

	hmacToken := hmac.New(sha256.New, []byte(srv.enrollmentSecret))
	hmacToken.Write([]byte(aid.ToString()))

	return hmacToken.Sum(nil)
}

func (srv *server) isWhitelistedForEnrollment(oID uuid.UUID, iID uuid.UUID) bool {
	defer srv.mu.RUnlock()
	srv.mu.RLock()

	for _, rule := range srv.enrollmentRules {
		if rule.OID == aID.OID && rule.IID == aID.IID {
			return true
		}
	}

	return false
}

func (srv *server) enrollClient(c *client) error {
	srv.mu.RLock()

	aID := c.AgentID()

	if !srv.isWhitelistedForEnrollment(aID.OID, aID.IID) {
		return errors.New(fmt.Sprintf("org or installer not whitelisted: %s / %s", aID.OID, aID.IID))
	}

	aID.Sid = uuid.New()
	c.setAgentID(aID)

	enrollmentToken := srv.generateEnrollmentToken(aID)

	if err := c.send(hcp.MODULE_ID_HCP, []*rpcm.Sequence{rpcm.NewSequence().
			AddInt8(rpcm.RP_TAGS_OPERATION, hcp.SET_HCP_ID).
			AddSequence(rpcm.RP_TAGS_HCP_IDENT, agentIdToSequence(ctx.aid)).
			AddBuffer(rpcm.RP_TAGS_HCP_ENROLLMENT_TOKEN, enrollmentToken)}); err != nil {
		return err
	}

	return nil
}

func (srv *server) getExpectedModulesFor(aID hcp.AgentID) []ModuleRule {
	defer srv.mu.RUnlock()
	srv.mu.Lock()

	var modules []ModuleRule
	for _, moduleInfo := range srv.moduleRules {
		if moduleInfo.AID.Matches(aID) {
			modules = append(modules, moduleInfo)
		}
	}

	return modules
}

func (srv *server) getHBSProfileFor(aID hcp.AgentID) ProfileRule , bool {
	defer srv.mu.RUnlock()
	srv.mu.Lock()

	for _, profile := range srv.profileRules {
		if profile.AID.Matches(aID) {
			return profile, true
		}
	}

	return ProfileRule{}, false
}

func (srv *server) GetChannels() connect chan hcp.AgentID, disconnect chan hcp.AgentID, incoming chan SensorMessage {
	defer srv.mu.Unlock()
	srv.mu.Lock()

	return srv.connectChannel, srv.disconnectChannel, srv.incomingChannel
}

func (srv *server) NewClient(sendFunc func(moduleID uint8, messages []*rpcm.Sequence) error) *Client {
	c = new(client)
	c.srv = srv
	c.sendCB = sendFunc
	c.isOnline = true

	return c
}

type client struct {
	sendMu sync.Mutex
	recvMu sync.Mutex
	srv *server
	isOnline bool
	isAuthenticated bool
	aID hcp.AgentID
	sendCB func(moduleID uint8, messages []*rpcm.Sequence) error
	incomingChannel chan SensorMessage
}

func (c *client) send(moduleID uint8, messages []*rpcm.Sequence) error {
	defer c.sendMu.Unlock()
	c.sendMu.Lock()

	if c.isOnline && c.isAuthenticated {
		return c.sendCB(moduleID, messages)
	}

	return errors.New("not connected or authenticated")
}

func (c *client) sendTimeSync() error {
	messages := []*rpcm.Sequence{rpcm.NewSequence().
			AddInt8(rpcm.RP_TAGS_OPERATION, hcp.SET_GLOBAL_TIME).
			AddTimestamp(rpcm.RP_TAGS_TIMESTAMP, uint64(time.Now().Unix()))}
	return c.send(hcp.MODULE_ID_HCP, messages)
}

func (c *client) AgentID() hcp.AgentID {
	return c.aID
}

func (c *client) setAgentID(aID hcp.AgentID) {
	c.aID = aID
}

func (c *client) Receive(moduleID uint8, messages []*rpcm.Sequence) error {
	defer c.recvMu.Unlock()
	c.recvMu.Lock()

	if !c.isOnline {
		return errors.New("not connected")
	}

	if !c.isAuthenticated {
		// Client must authenticate first
		if moduleId != hcp.MODULE_ID_HCP {
			defer 
			return errors.New("expected authentication first")
		}

		headers := messages.ToMachine()[0].(rpcm.MachineSequence)
		hostName := headers[rpcm.RP_TAGS_HOST_NAME]
		internalIp := headers[rpcm.RP_TAGS_IP_ADDRESS]
		if err := c.aID.FromSequence(headers[rpcm.RP_TAGS_HCP_IDENT].(rpcm.MachineSequence)); err != nil {
			return err
		}

		if !c.aID.IsAbsolute() && !c.srv.isDebug {
			return errors.New("invalid AID")
		}

		if c.aID.IsSIDWild() {
			// This sensor requires enrollment
			if err := c.srv.enrollClient(c); err != nil {
				return err
			}
		} else {
			// This sensor should already be enrolled with a valid token
			sensorToken, ok := headers[rpcm.RP_TAGS_HCP_ENROLLMENT_TOKEN].([]byte)
			if !ok {
				return errors.New("sensor has no enrollment token")
			}
			if !c.srv.validateEnrollmentToken(c.aID, sensorToken) {
				return errors.New("invalid enrollment token")
			}
		}

		// Upon authentication we send an initial clock sync
		if err := c.send(hcp.MODULE_ID_HCP, []*rpcm.Sequence{rpcm.NewSequence().
				AddInt8(rpcm.RP_TAGS_OPERATION, hcp.SET_GLOBAL_TIME).
				AddTimestamp(rpcm.RP_TAGS_TIMESTAMP, uint64(time.Now().Unix()))}); err != nil {
			return err
		}

		// Publish the connection event and keep a reference to the incoming channel to use later
		connectChannel, _, incomingChannel := c.srv.GetChannels()
		connectChannel <- c.aID
		c.incomingChannel = incomingChannel

		c.isAuthenticated = true
	}

	// By this point we are either a valid returning client or a newly enrolled one

	switch moduleID {
	case hcp.MODULE_ID_HCP:
		err = c.processHCPMessage(messages)
	case hcp.MODULE_ID_HBS:
		err = c.processHBSMessage(messages)
	default:
		return errors.New(fmt.Sprintf("received messages from unexpected module: %d", moduleId))
	}

	return nil
}

func (c *client) processHCPMessage(messages []*rpcm.Sequence) error {
	shouldBeLoaded := c.srv.getExpectedModulesFor(c.aID)

	var currentlyLoaded []moduleRule
	for _, message := range messages {
		if modules, ok := message.GetList(rpcm.RP_TAGS_HCP_MODULES); ok {
			for _, moduleInfo := range modules.GetSequence(rpcm.RP_TAGS_HCP_MODULE) {
				var mod ModuleRule
				var ok bool
				if mod.Hash, ok = moduleInfo.GetBuffer(rpcm.RP_TAGS_HASH); !ok {
					return errors.New("module entry missing hash")
				}
				if mod.ModuleID, ok = moduleInfo.GetInt8(rpcm.RP_TAGS_HCP_MODULE_ID); !ok {
					return errors.New("module entry missing module ID")
				}

				currentlyLoaded = append(currentlyLoaded, mod)
			}
		}
	}

	outMessages := make([]*rpcm.Sequence, 5)

	// Look for modules that should be unloaded
	for _, modIsLoaded := range currentlyLoaded {
		var isFound bool
		for _, modShouldBeLoaded := range shouldBeLoaded {
			if modIsLoaded.ModuleID == modShouldBeLoaded.ModuleID &&
				modIsLoaded.Hash == modShouldBeLoaded.Hash {
				isFound = true
				break
			}
		}

		if !isFound {
			outMessages = append(outMessages, rpcm.NewSequence().
					AddInt8(rpcm.RP_TAGS_OPERATION, hcp.UNLOAD_MODULE).
					AddInt8(rpcm.RP_TAGS_HCP_MODULE_ID, modIsLoaded.ModuleID))
		}
	}

	// Look for modules that need to be loaded
	for _, modShouldBeLoaded := range shouldBeLoaded {
		var isFound bool
		for _, modIsLoaded := range currentlyLoaded {
			if modIsLoaded.ModuleID == modShouldBeLoaded.ModuleID &&
				modIsLoaded.Hash == modShouldBeLoaded.Hash {
				isFound = true
				break
			}
		}

		if !isFound {
			var err error
			var moduleContent []byte
			var moduleSig []byte
			if moduleContent, err = ioutil.ReadFile(modShouldBeLoaded.ModuleFile); err != nil {
				return err
			}
			if moduleSig, err = ioutil.ReadFile(fmt.Sprintf("%s.sig", modShouldBeLoaded.ModuleFile)); err != nil {
				return err
			}

			outMessages = append(outMessages, rpcm.NewSequence().
					AddInt8(rpcm.RP_TAGS_OPERATION, hcp.LOAD_MODULE).
					AddInt8(rpcm.RP_TAGS_HCP_MODULE_ID, modShouldBeLoaded.ModuleID).
					AddBuffer(rpcm.RP_TAGS_BINARY, moduleContent).
					AddBuffer(rpcm.RP_TAGS_SIGNATURE, moduleSig))
		}
	}

	// We also take the sync opportunity to send a time sync
	outMessages = append(outMessages, rpcm.NewSequence().
			AddInt8(rpcm.RP_TAGS_OPERATION, hcp.SET_GLOBAL_TIME).
			AddTimestamp(rpcm.RP_TAGS_TIMESTAMP, uint64(time.Now().Unix())))

	if err = c.send(hcp.MODULE_ID_HCP, outMessages); err != nil {
		return err
	}
}

func (c *client) processHBSMessage(messages []*rpcm.Sequence) error {
	outMessages := make([]*rpcm.Sequence, 1)

	for _, message := range messages {
		if syncMessage, ok := message.GetSequence(rpcm.RP_TAGS_NOTIFICATION_SYNC); ok {
			if profile, ok := c.srv.getHBSProfileFor(c.aID); !ok {
				return errors.New("no HBS profile to load")
			}

			if currentProfileHash, ok := syncMessage.GetBuffer(rpcm.RP_TAGS_HASH); ok {
				if bytes.Equal(profile.Hash, currentProfileHash) {
					// The sensor already has the latest profile
					continue
				}
			}

			var profileContent []byte
			if profileContent, err = ioutil.ReadFile(profile.ProfileFile); err != nil {
				return err
			}

			actualHash := sha256.Sum256(profileContent)

			if !bytes.Equal(actualHash[:], profile.Hash) {
				return errors.New(fmt.Sprintf("profile content seems to have changed"))
			}

			parsedProfile := rpcm.NewList(0, 0)
			if err = parsedProfile.Deserialize(bytes.NewBuffer(profileContent)); err != nil {
				return err
			}

			outMessages = append(outMessages, rpcm.NewSequence().
					AddSequence(rpcm.RP_TAGS_NOTIFICATION_SYNC, rpcm.NewSequence().
					AddBuffer(rpcm.RP_TAGS_HASH, expectedHash[:]).
					AddList(rpcm.RP_TAGS_HBS_CONFIGURATIONS, parsedProfile)))
		} else {
			var data SensorMessage
			data.Event = message
			data.AID = &c.aID
			g_configs.collectionLog <- data
		}
	}
}

func (c *client) Close() {
	// Notify consumers that this client is now offline
	_, disconnectChannel, _ := c.srv.GetChannels()
	disconnectChannel <- c.aID

	c.srv.mu.Lock()

	if c.isAuthenticated {
		delete(c.srv.online, c.aID)
	}

	c.srv.mu.Unlock()

	defer c.sendMu.Unlock()
	defer c.recvMu.Unlock()
	c.sendMu.Lock()
	c.recvMu.Lock()
	c.isAuthenticated = false
	c.isOnline = false
}