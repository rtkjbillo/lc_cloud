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

package main

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/lc_server_config"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/rpcm"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/utils"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"
)

const (
	MAX_INBOUND_FRAME_SIZE = (1024 * 1024 * 50)
)

var g_configs struct {
	sync.RWMutex
	isDebug          bool
	isStdOut         bool
	isDraining       bool
	isDrained        bool
	outputGoRoutines sync.WaitGroup
	activeGoRoutines sync.WaitGroup
	collectionLog    chan collectionData
	config           *LcServerConfig.Config
	clients          struct {
		sync.RWMutex
		context map[string]*clientContext
	}
	enrollmentRules map[string]map[string]bool
	moduleRules     []moduleRule
	hbsProfiles     []profileRule
}

type clientContext struct {
	conn net.Conn
	aid  hcp.AgentId
}

type moduleRule struct {
	aid      hcp.AgentId
	moduleId uint8
	hash     [32]byte
	filePath string
}

type profileRule struct {
	aid      hcp.AgentId
	hash     [32]byte
	filePath string
}

type collectionData struct {
	message *rpcm.Sequence
	aid     *hcp.AgentId
}

//=============================================================================
//	Helper Functions
//=============================================================================

func agentIdFromSequence(message rpcm.MachineSequence) hcp.AgentId {
	var aid hcp.AgentId

	copy(aid.Oid[:], message[rpcm.RP_TAGS_HCP_ORG_ID].([]byte))
	copy(aid.Iid[:], message[rpcm.RP_TAGS_HCP_INSTALLER_ID].([]byte))
	copy(aid.Sid[:], message[rpcm.RP_TAGS_HCP_SENSOR_ID].([]byte))
	aid.Architecture, _ = message[rpcm.RP_TAGS_HCP_ARCHITECTURE].(uint32)
	aid.Platform, _ = message[rpcm.RP_TAGS_HCP_PLATFORM].(uint32)

	return aid
}

func agentIdToSequence(aid hcp.AgentId) *rpcm.Sequence {
	seq := rpcm.NewSequence().
		AddBuffer(rpcm.RP_TAGS_HCP_ORG_ID, aid.Oid[:]).
		AddBuffer(rpcm.RP_TAGS_HCP_INSTALLER_ID, aid.Iid[:]).
		AddBuffer(rpcm.RP_TAGS_HCP_SENSOR_ID, aid.Sid[:]).
		AddInt32(rpcm.RP_TAGS_HCP_ARCHITECTURE, aid.Platform).
		AddInt32(rpcm.RP_TAGS_HCP_PLATFORM, aid.Architecture)

	return seq
}

func reloadConfigs(configFile string) error {
	var err error
	var configContent []byte

	glog.Info("loading config")
	tmpConfig := new(LcServerConfig.Config)
	if configContent, err = ioutil.ReadFile(configFile); err == nil {
		if err = proto.UnmarshalText(string(configContent), tmpConfig); err == nil {
			newEnrollmentRules := make(map[string]map[string]bool, 0)
			i := 0
			for _, rule := range tmpConfig.GetEnrollmentRules().GetRule() {
				if newEnrollmentRules[rule.GetOid()] == nil {
					newEnrollmentRules[rule.GetOid()] = make(map[string]bool, 1)
				}
				newEnrollmentRules[rule.GetOid()][rule.GetIid()] = true
				i++
			}

			glog.Infof("enrollment Rules: %d", i)

			newModuleRules := make([]moduleRule, 0)
			for _, rule := range tmpConfig.GetModuleRules().GetRule() {
				var moduleInfo moduleRule
				if !moduleInfo.aid.FromString(rule.GetAid()) {
					glog.Errorf("badly formated AID in Module Rule (%s), skipping", rule.GetAid())
					continue
				}
				moduleInfo.moduleId = uint8(rule.GetModuleId())
				moduleInfo.filePath = rule.GetModuleFile()

				var fileContent []byte
				if fileContent, err = ioutil.ReadFile(moduleInfo.filePath); err == nil {
					moduleInfo.hash = sha256.Sum256(fileContent)
				} else {
					glog.Errorf("error reading Module file (%s), skipping: %s", moduleInfo.filePath, err)
					continue
				}

				if _, err = os.Stat(fmt.Sprintf("%s.sig", moduleInfo.filePath)); err != nil {
					glog.Errorf("error reading Module signature file (%s), skipping: %s", moduleInfo.filePath, err)
					continue
				}

				newModuleRules = append(newModuleRules, moduleInfo)
			}

			glog.Infof("module Rules: %d", len(newModuleRules))

			newProfiles := make([]profileRule, 0)
			for _, rule := range tmpConfig.GetProfileRules().GetRule() {
				var profileInfo profileRule
				if !profileInfo.aid.FromString(rule.GetAid()) {
					glog.Errorf("eadly formated AID in HBS Profile Rule (%s), skipping", rule.GetAid())
					continue
				}

				profileInfo.filePath = rule.GetProfileFile()

				var fileContent []byte
				if fileContent, err = ioutil.ReadFile(profileInfo.filePath); err == nil {
					profileInfo.hash = sha256.Sum256(fileContent)
				} else {
					glog.Errorf("error reading HBS Profile file (%s), skipping: %s", profileInfo.filePath, err)
					continue
				}

				newProfiles = append(newProfiles, profileInfo)
			}

			glog.Infof("hbs Profiles: %d", len(newProfiles))

			g_configs.Lock()

			g_configs.config = tmpConfig
			g_configs.enrollmentRules = newEnrollmentRules
			g_configs.moduleRules = newModuleRules
			g_configs.hbsProfiles = newProfiles

			g_configs.Unlock()
		}
	}

	if err != nil {
		glog.Fatalf("error loading config: %s", err)
	}

	return err
}

//=============================================================================
//	GoRoutines
//=============================================================================
func watchForConfigChanges(configFile string) {
	var lastFileInfo os.FileInfo
	var err error

	defer g_configs.activeGoRoutines.Done()

	if lastFileInfo, err = os.Stat(configFile); err != nil {
		glog.Errorf("could not get initial config modification time, won't detect changes and reload automatically: %s", err)
		return
	}

	for !g_configs.isDraining {
		if newFileInfo, err := os.Stat(configFile); err == nil && newFileInfo.ModTime() != lastFileInfo.ModTime() {
			glog.Info("detected a change in configuration, reloading.")
			lastFileInfo = newFileInfo
			reloadConfigs(configFile)
		}

		time.Sleep(30 * time.Second)
	}
}

func logCollection(outputFile string) {
	var err error
	defer g_configs.outputGoRoutines.Done()
	var fileHandle *os.File
	nextFileCycle := time.Now().Add(60 * time.Minute)

	if outputFile != "" {
		glog.Infof("opening collection log file: %s", outputFile)
		fileHandle, err = os.Create(outputFile)
		if err != nil {
			glog.Fatalf("could not open collection log file: %s", err)
		}
	}

	for !g_configs.isDraining {
		var collection collectionData

		timeout := make(chan bool, 1)
		go func() {
			time.Sleep(10 * time.Second)
			timeout <- true
		}()

		select {
		case collection = <-g_configs.collectionLog:
		case <-timeout:
			if g_configs.isDrained {
				return
			}
		}

		if collection.message == nil {
			continue
		}

		if time.Now().After(nextFileCycle) {
			glog.Info("cycling collection log file")

			nextFileCycle = time.Now().Add(60 * time.Minute)

			fileHandle.Close()
			if err = os.Rename(outputFile, outputFile+".1"); err != nil {
				glog.Fatalf("could not move collection file to old: %s", err)
			}
			if fileHandle, err = os.Create(outputFile); err != nil {
				glog.Fatalf("could not open collection log file: %s", err)
			}
		}

		wrapper := make(map[string]interface{}, 2)
		wrapper["event"] = collection.message.ToJson()
		wrapper["routing"] = make(map[string]string, 1)
		wrapper["routing"].(map[string]string)["aid"] = collection.aid.ToString()

		if g_configs.isStdOut {
			if jsonMessage, err := json.MarshalIndent(wrapper, "", "    "); err != nil {
				glog.Errorf("error displaying collection: %s", err)
			} else {
				fmt.Print(string(jsonMessage))
			}
		}

		if fileHandle != nil {
			if jsonMessage, err := json.Marshal(wrapper); err != nil {
				glog.Errorf("error displaying collection: %s", err)
			} else {
				fileHandle.Write(jsonMessage)
			}
		}
	}

	if fileHandle != nil {
		fileHandle.Close()
	}
}

func handleClient(conn net.Conn) {
	var ctx clientContext
	defer conn.Close()
	defer g_configs.activeGoRoutines.Done()

	ctx.conn = conn
	var moduleId uint8
	var messages *rpcm.List
	var err error

	if moduleId, messages, err = recvFrame(&ctx, 30*time.Second); err != nil {
		glog.Errorf("failed to receive headers: %s", err)
		return
	}

	if moduleId != hcp.MODULE_ID_HCP {
		glog.Warningf("received unexpected frames from module instead of headers: %d", moduleId)
		return
	}

	headers := messages.ToMachine()[0].(rpcm.MachineSequence)

	hostName := headers[rpcm.RP_TAGS_HOST_NAME]
	internalIp := headers[rpcm.RP_TAGS_IP_ADDRESS]
	aid := agentIdFromSequence(headers[rpcm.RP_TAGS_HCP_IDENT].(rpcm.MachineSequence))
	glog.Infof("Initial contact: %s / %s / 0x%08x", hostName, aid.ToString(), internalIp)
	if !aid.IsAbsolute() && !g_configs.isDebug {
		glog.Warningf("invalid agent id containing wildcard")
		return
	}

	ctx.aid = aid

	if aid.IsSidWild() {
		glog.Infof("sensor requires enrollment")
		if !processEnrollment(&ctx) {
			return
		}
	} else {
		sensorToken, ok := headers[rpcm.RP_TAGS_HCP_ENROLLMENT_TOKEN].([]byte)
		if !ok {
			glog.Warningf("missing enrollment token from sensor")
			return
		}

		if validateEnrollmentToken(aid, sensorToken) {
			glog.Infof("enrollment token OK")
		} else {
			glog.Warningf("invalid enrollment token")
			return
		}
	}

	if err = sendTimeSync(&ctx); err != nil {
		glog.Warningf("error sending time sync message: %s", err)
		return
	}

	g_configs.RLock()
	g_configs.clients.Lock()

	g_configs.clients.context[aid.ToString()] = &ctx
	defer func() {
		g_configs.RLock()
		g_configs.clients.Lock()
		delete(g_configs.clients.context, aid.ToString())
		g_configs.clients.Unlock()
		g_configs.RUnlock()
	}()

	g_configs.clients.Unlock()
	g_configs.RUnlock()

	glog.Infof("client %s registered, beginning to receive data", aid.ToString())

	for !g_configs.isDraining {
		if moduleId, messages, err = recvFrame(&ctx, 30*time.Second); err != nil {
			break
		}

		switch moduleId {
		case hcp.MODULE_ID_HCP:
			err = processHCPMessage(&ctx, messages)
		case hcp.MODULE_ID_HBS:
			err = processHBSMessage(&ctx, messages)
		default:
			glog.Warningf("received messages from unexpected module: %d", moduleId)
		}
	}

	glog.Infof("client %s disconnected", ctx.aid.ToString())
}

//=============================================================================
//	TLS Server Helper Functions
//=============================================================================
func sendFrame(ctx *clientContext, moduleId uint8, messages []*rpcm.Sequence, timeout time.Duration) error {
	var err error
	endTime := time.Now().Add(timeout)
	frameData := bytes.Buffer{}
	if err = binary.Write(&frameData, binary.BigEndian, moduleId); err != nil {
		return err
	}

	messageBundle := rpcm.NewList(rpcm.RP_TAGS_MESSAGE, rpcm.RPCM_SEQUENCE)
	for _, message := range messages {
		if messageBundle = messageBundle.AddSequence(message); messageBundle == nil {
			return errors.New("failed to bundle messages")
		}
	}

	if err = messageBundle.Serialize(&frameData); err != nil {
		return err
	}

	frameWrapper := bytes.Buffer{}
	if err = binary.Write(&frameWrapper, binary.BigEndian, uint32(frameData.Len())); err != nil {
		return err
	}

	zlibWriter := zlib.NewWriter(&frameWrapper)
	zlibWriter.Write(frameData.Bytes())
	zlibWriter.Close()

	finalFrame := bytes.Buffer{}
	if err = binary.Write(&finalFrame, binary.BigEndian, uint32(frameWrapper.Len())); err != nil {
		return err
	}

	finalFrame.Write(frameWrapper.Bytes())

	if err = sendData(ctx.conn, finalFrame.Bytes(), endTime); err != nil {
		return err
	}

	return err
}

func recvFrame(ctx *clientContext, timeout time.Duration) (uint8, *rpcm.List, error) {
	var err error
	var endTime time.Time
	var moduleId uint8
	var buf []byte
	var frameSize uint32

	if timeout != 0 {
		endTime = time.Now().Add(timeout)
	}

	received := rpcm.NewList(rpcm.RP_TAGS_MESSAGE, rpcm.RPCM_SEQUENCE)

	if buf, err = recvData(ctx.conn, 4, endTime); buf == nil || err != nil {
		return 0, nil, err
	}

	if err = binary.Read(bytes.NewBuffer(buf), binary.BigEndian, &frameSize); err != nil {
		return 0, nil, err
	}

	if MAX_INBOUND_FRAME_SIZE < frameSize {
		return 0, nil, errors.New("frame size indicated too large or not a multiple of block size")
	}

	if buf, err = recvData(ctx.conn, uint(frameSize), endTime); buf == nil || err != nil || len(buf) == 0 {
		return 0, nil, err
	}

	zlibReader, err := zlib.NewReader(bytes.NewReader(buf))
	if err != nil {
		return 0, nil, err
	}

	var decompressedBuf bytes.Buffer
	if size, err := io.Copy(&decompressedBuf, zlibReader); err != nil || 0 >= size {
		if err != nil {
			return 0, nil, err
		} else {
			return 0, nil, errors.New("received empty frame")
		}
	}

	if moduleId, err = decompressedBuf.ReadByte(); err != nil {
		return 0, nil, err
	}

	if err = received.Deserialize(&decompressedBuf); err != nil {
		return 0, nil, err
	}

	return moduleId, received, err
}

func recvData(conn net.Conn, size uint, timeout time.Time) ([]byte, error) {
	buf := make([]byte, size)
	var receivedLen uint
	var err error

	if !timeout.IsZero() {
		conn.SetReadDeadline(timeout)
	}

	for receivedLen < size {
		msgLen := 0
		msgLen, err = conn.Read(buf[receivedLen:])
		if msgLen > 0 {
			receivedLen += uint(msgLen)
		}
		if err != nil {
			break
		}
	}

	if err != nil {
		buf = nil
	}

	return buf, err
}

func sendData(conn net.Conn, buf []byte, timeout time.Time) error {
	var err error

	if !timeout.IsZero() {
		conn.SetWriteDeadline(timeout)
	}

	var totalSent int

	for totalSent < len(buf) {
		nSent, err := conn.Write(buf)

		if nSent > 0 {
			totalSent += nSent
		}

		if err != nil {
			return err
		}
	}

	return err
}

//=============================================================================
//	Main Entrypoint
//=============================================================================
func main() {
	var err error

	isDebug := flag.Bool("debug", false, "start server in debug mode")
	isOutputToStdout := flag.Bool("stdout", false, "outputs traffic from sensors to stdout")
	outputLogFile := flag.String("output_file", "", "file where collection from sensors should be written to")
	configFile := flag.String("conf", "lc_config.pb.txt", "path to config file")
	listenIface := flag.String("listen", "0.0.0.0:443", "the interface and port to listen for connections on")
	flag.Parse()

	glog.Info("starting LC Termination Server")

	interruptsChannel := make(chan os.Signal, 1)
	signal.Notify(interruptsChannel, os.Interrupt)
	go func() {
		<-interruptsChannel
		glog.Info("received exiting signal")
		g_configs.isDraining = true
	}()

	glog.Info("loading private key")
	cert, err := tls.LoadX509KeyPair("./c2_cert.pem", "./c2_key.pem")
	if err != nil {
		glog.Fatalf("failed to load cert and key: %s", err)
	}

	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	tlsConfig.Rand = rand.Reader

	if *isDebug {
		g_configs.isDebug = true
		glog.Infof("server is in debug mode")
	}

	if *isOutputToStdout {
		g_configs.isStdOut = true
		glog.Info("outputing sensor traffic to stdout")
	}

	g_configs.clients.context = make(map[string]*clientContext, 0)

	if err = reloadConfigs(*configFile); err != nil {
		glog.Fatalf("could not load initial configs, exiting.")
	}

	resolvedAddr, err := net.ResolveTCPAddr("tcp", *listenIface)

	if err != nil {
		glog.Fatalf("failed to resolve listen address: %s", err)
	}

	listenSocket, err := net.ListenTCP("tcp", resolvedAddr)
	if err != nil {
		glog.Fatalf("could not open %s for listening: %s",
			listenIface,
			err.Error())
	}

	g_configs.activeGoRoutines.Add(1)
	go watchForConfigChanges(*configFile)

	g_configs.collectionLog = make(chan collectionData, 1000)
	g_configs.outputGoRoutines.Add(1)
	go logCollection( *outputLogFile )

	glog.Infof("listening on %s", *listenIface)

	for {

		if g_configs.isDraining {
			break
		}

		listenSocket.SetDeadline(time.Now().Add(5 * time.Second))
		conn, err := listenSocket.Accept()

		if g_configs.isDraining {
			break
		}

		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			glog.Fatalf("error accepting on socket: %s", err.Error())
		}

		conn = tls.Server(conn, &tlsConfig)

		g_configs.activeGoRoutines.Add(1)
		go handleClient(conn)
	}

	glog.Info("draining, waiting on handlers to exit")
	listenSocket.Close()
	g_configs.activeGoRoutines.Wait()
	g_configs.isDrained = true
	g_configs.outputGoRoutines.Wait()
	glog.Info("drained, exiting")
}

//=============================================================================
//	Handlers & HCP Functionality
//=============================================================================
func validateEnrollmentToken(aid hcp.AgentId, token []byte) bool {
	g_configs.RLock()

	hmacToken := hmac.New(sha256.New, []byte(g_configs.config.GetSecretEnrollmentToken()))

	g_configs.RUnlock()

	hmacToken.Write([]byte(aid.ToString()))
	expectedToken := hmacToken.Sum(nil)
	return hmac.Equal(token, expectedToken)
}

func generateEnrollmentToken(aid hcp.AgentId) []byte {
	g_configs.RLock()

	hmacToken := hmac.New(sha256.New, []byte(g_configs.config.GetSecretEnrollmentToken()))

	g_configs.RUnlock()

	hmacToken.Write([]byte(aid.ToString()))
	return hmacToken.Sum(nil)
}

func sendTimeSync(ctx *clientContext) error {
	var messages []*rpcm.Sequence
	messages = append(messages, rpcm.NewSequence().
		AddInt8(rpcm.RP_TAGS_OPERATION, hcp.SET_GLOBAL_TIME).
		AddTimestamp(rpcm.RP_TAGS_TIMESTAMP, uint64(time.Now().Unix())))
	err := sendFrame(ctx, hcp.MODULE_ID_HCP, messages, 10*time.Second)
	return err
}

func processEnrollment(ctx *clientContext) bool {
	var isWhitelisted bool
	var isEnrolled bool
	g_configs.RLock()

	if g_configs.enrollmentRules[ctx.aid.Oid.String()][ctx.aid.Iid.String()] {
		isWhitelisted = true
	} else {
		glog.Warningf("sensor is not whitelisted for enrollment( OID:%s, IID:%s )", ctx.aid.Oid.String(), ctx.aid.Iid.String())
	}

	g_configs.RUnlock()

	if isWhitelisted {
		ctx.aid.Sid = uuid.New()
		enrollmentToken := generateEnrollmentToken(ctx.aid)

		var messages []*rpcm.Sequence
		messages = append(messages, rpcm.NewSequence().
			AddInt8(rpcm.RP_TAGS_OPERATION, hcp.SET_HCP_ID).
			AddSequence(rpcm.RP_TAGS_HCP_IDENT, agentIdToSequence(ctx.aid)).
			AddBuffer(rpcm.RP_TAGS_HCP_ENROLLMENT_TOKEN, enrollmentToken))
		if err := sendFrame(ctx, hcp.MODULE_ID_HCP, messages, 10*time.Second); err == nil {
			isEnrolled = true
			glog.Infof("sensor enrolled: %s", ctx.aid.ToString())
		} else {
			glog.Warningf("failed to send enrollment to sensor: %s", err)
		}
	}

	return isEnrolled
}

func processHCPMessage(ctx *clientContext, messages *rpcm.List) error {
	var err error

	var shouldBeLoaded []*moduleRule
	g_configs.RLock()
	for _, moduleInfo := range g_configs.moduleRules {
		if moduleInfo.aid.Matches(ctx.aid) {
			shouldBeLoaded = append(shouldBeLoaded, &moduleInfo)
		}
	}
	g_configs.RUnlock()

	var currentlyLoaded []moduleRule
	for _, message := range messages.GetSequence(rpcm.RP_TAGS_MESSAGE) {
		if modules, ok := message.GetList(rpcm.RP_TAGS_HCP_MODULES); ok {
			for _, moduleInfo := range modules.GetSequence(rpcm.RP_TAGS_HCP_MODULE) {
				var hash []byte
				var moduleId uint8
				var mod moduleRule
				var ok bool
				if hash, ok = moduleInfo.GetBuffer(rpcm.RP_TAGS_HASH); !ok {
					continue
				}
				if moduleId, ok = moduleInfo.GetInt8(rpcm.RP_TAGS_HCP_MODULE_ID); !ok {
					continue
				}

				mod.moduleId = moduleId
				copy(mod.hash[:], hash)
				currentlyLoaded = append(currentlyLoaded, mod)
			}
		}
	}

	var outMessages []*rpcm.Sequence
	nLoading := 0
	nUnloading := 0

	for _, modIsLoaded := range currentlyLoaded {
		var isFound bool
		for _, modShouldBeLoaded := range shouldBeLoaded {
			if modIsLoaded.moduleId == modShouldBeLoaded.moduleId &&
				modIsLoaded.hash == modShouldBeLoaded.hash {
				isFound = true
				break
			}
		}

		if !isFound {
			nUnloading++
			outMessages = append(outMessages, rpcm.NewSequence().
				AddInt8(rpcm.RP_TAGS_OPERATION, hcp.UNLOAD_MODULE).
				AddInt8(rpcm.RP_TAGS_HCP_MODULE_ID, modIsLoaded.moduleId))
		}
	}

	for _, modShouldBeLoaded := range shouldBeLoaded {
		var isFound bool
		for _, modIsLoaded := range currentlyLoaded {
			if modIsLoaded.moduleId == modShouldBeLoaded.moduleId &&
				modIsLoaded.hash == modShouldBeLoaded.hash {
				isFound = true
				break
			}
		}

		if !isFound {
			var moduleContent []byte
			var moduleSig []byte
			if moduleContent, err = ioutil.ReadFile(modShouldBeLoaded.filePath); err != nil {
				glog.Errorf("failed to get module content (%s): %s", modShouldBeLoaded.filePath, err)
				continue
			}
			if moduleSig, err = ioutil.ReadFile(fmt.Sprintf("%s.sig", modShouldBeLoaded.filePath)); err != nil {
				glog.Errorf("failed to get module signature (%s.sig): %s", modShouldBeLoaded.filePath, err)
				continue
			}

			nLoading++
			outMessages = append(outMessages, rpcm.NewSequence().
				AddInt8(rpcm.RP_TAGS_OPERATION, hcp.LOAD_MODULE).
				AddInt8(rpcm.RP_TAGS_HCP_MODULE_ID, modShouldBeLoaded.moduleId).
				AddBuffer(rpcm.RP_TAGS_BINARY, moduleContent).
				AddBuffer(rpcm.RP_TAGS_SIGNATURE, moduleSig))
		}
	}

	glog.Infof("sync from %s, loading %d unloading %d", ctx.aid.ToString(), nLoading, nUnloading)

	err = sendFrame(ctx, hcp.MODULE_ID_HCP, outMessages, 120*time.Second)

	return err
}

func processHBSMessage(ctx *clientContext, messages *rpcm.List) error {
	var err error

	var outMessages []*rpcm.Sequence

	for _, message := range messages.GetSequence(rpcm.RP_TAGS_MESSAGE) {
		if syncMessage, ok := message.GetSequence(rpcm.RP_TAGS_NOTIFICATION_SYNC); ok {
			var profileToSend string
			var expectedHash [32]byte
			currentProfileHash, _ := syncMessage.GetBuffer(rpcm.RP_TAGS_HASH)

			g_configs.RLock()
			for _, profile := range g_configs.hbsProfiles {
				if profile.aid.Matches(ctx.aid) {
					if currentProfileHash == nil || !bytes.Equal(profile.hash[:], currentProfileHash) {
						profileToSend = profile.filePath
						expectedHash = profile.hash
					}
					break
				}
			}
			g_configs.RUnlock()

			if profileToSend != "" {
				var profileContent []byte
				if profileContent, err = ioutil.ReadFile(profileToSend); err != nil {
					glog.Errorf("failed to get profile content (%s): %s", profileToSend, err)
					continue
				}

				currentHash := sha256.Sum256(profileContent)

				if !bytes.Equal(currentHash[:], expectedHash[:]) {
					glog.Errorf("profile content seems to have changed!")
					continue
				}

				parsedProfile := rpcm.NewList(0, 0)
				if err = parsedProfile.Deserialize(bytes.NewBuffer(profileContent)); err != nil {
					glog.Errorf("failed to deserialize profile (%s): %s", profileToSend, err)
					continue
				}

				outMessages = append(outMessages, rpcm.NewSequence().
					AddSequence(rpcm.RP_TAGS_NOTIFICATION_SYNC,
						rpcm.NewSequence().
							AddBuffer(rpcm.RP_TAGS_HASH, expectedHash[:]).
							AddList(rpcm.RP_TAGS_HBS_CONFIGURATIONS,
								parsedProfile)))
			}
		} else {
			var data collectionData
			data.message = message
			data.aid = &ctx.aid
			g_configs.collectionLog <- data
		}
	}

	err = sendFrame(ctx, hcp.MODULE_ID_HBS, outMessages, 120*time.Second)

	return err
}
