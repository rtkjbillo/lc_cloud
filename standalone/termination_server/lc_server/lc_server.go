package main

import (
	"log"
	"net"
	"os"
	"io"
	"time"
	"fmt"
	"bytes"
	"flag"
	"errors"
	"io/ioutil"
	"encoding/binary"
	"compress/zlib"
	"crypto/rand"
	"crypto/tls"
	"crypto/sha256"
	"crypto/hmac"
	"github.com/google/uuid"
	"github.com/golang/protobuf/proto"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/lc_server_config"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/rpcm"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/utils"
)

const (
	MAX_INBOUND_FRAME_SIZE = (1024 * 1024 * 50)
)

var g_config *LcServerConfig.Config
var g_clients map[string]*ClientContext
var g_isDebug bool


func validateEnrollmentToken(aid hcp.AgentId, token []byte) bool {
	hmacToken := hmac.New(sha256.New, []byte(g_config.GetSecretEnrollmentToken()))
	hmacToken.Write([]byte(aid.ToString()))
	expectedToken := hmacToken.Sum(nil)
	return hmac.Equal(token, expectedToken)
}

type ClientContext struct {
	conn net.Conn
	aid *hcp.AgentId
}

func main() {
	var err error
	log.Println("Starting LC Termination Server")

	log.Println("Loading private key")
	cert, err := tls.LoadX509KeyPair("./c2_cert.pem", "./c2_key.pem")
	if err != nil {
		log.Fatalf("Failed to load cert and key: %s", err)
		os.Exit(1)
	}

	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	tlsConfig.Rand = rand.Reader

	isDebug := flag.Bool("debug", false, "start server in debug mode")
	configFile := flag.String("conf", "lc_config.pb.txt", "path to config file")
	flag.Parse()

	if *isDebug {
		g_isDebug = true
		log.Printf("Server is in debug mode")
	}

	log.Println("Loading config")
	g_config := new(LcServerConfig.Config)
	if configContent, err := ioutil.ReadFile(*configFile); err == nil {
		if err = proto.UnmarshalText(string(configContent), g_config); err != nil {
			log.Fatalf("Invalid config: %s", err)
			os.Exit(1)
		}
	} else {
		log.Fatalf("Failed to load protobuf text config (%s): %s", *configFile, err)
	}

	listenSocket, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", g_config.GetListenIface(), g_config.GetListenPort()), &tlsConfig)

	if err != nil {
		log.Fatalf("Could not open %s:%d for listening: %s", g_config.GetListenIface(), g_config.GetListenPort(), err.Error())
		os.Exit(1)
	}

	defer listenSocket.Close()

	log.Printf("Listening on %s:%d", g_config.GetListenIface(), g_config.GetListenPort())

	for {
		conn, err := listenSocket.Accept()

		if err != nil {
			log.Printf("Error accepting on socket: %s", err.Error())
			os.Exit(1)
		}

		log.Printf("Handing out new connection to handler")
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	var ctx ClientContext
	defer conn.Close()

	ctx.conn = conn
	var moduleId uint8
	var messages *rpcm.List
	var err error

	if moduleId, messages, err = recvFrame(&ctx, 30 * time.Second); err != nil {
		log.Printf("Failed to receive headers: %s", err)
		return
	}

	if moduleId != hcp.MODULE_ID_HCP {
		log.Printf("Received unexpected frames from module instead of headers: %d", moduleId)
		return
	}

	headers := messages.ToMachine()[0].(rpcm.MachineSequence)

	hostName := headers[rpcm.RP_TAGS_HOST_NAME]
	internalIp := headers[rpcm.RP_TAGS_IP_ADDRESS]
	aid := agentIdFromMessage(headers[rpcm.RP_TAGS_HCP_IDENT].(rpcm.MachineSequence))
	log.Printf("Initial contact: %s / %s / 0x%08x", hostName, aid.ToString(), internalIp)
	if !aid.IsAbsolute() && !g_isDebug {
		log.Printf("Invalid agent id containing wildcard")
		return
	}
	if aid.IsSidWild() {
		log.Printf("Sensor requires enrollment")
		log.Printf("TODO(maximelb): Write enrollment logic")
	}

	ctx.aid = &aid

	sensorToken, ok := headers[rpcm.RP_TAGS_HCP_ENROLLMENT_TOKEN].([]byte)
	if !ok {
		log.Printf("Missing enrollment token from sensor")
		return
	}

	if !validateEnrollmentToken(aid, sensorToken) {
		log.Printf("Invalid enrollment token")
		return
	}
	
	if err = sendTimeSync(&ctx); err != nil {
		log.Printf("Error sending time sync message: %s", err)
		return
	}

	g_clients[aid.ToString()] = &ctx
	log.Printf("Client %s registered, beginning to receive data", aid.ToString())

	for err != nil {
		if moduleId, messages, err = recvFrame(&ctx, 30 * time.Second); err != nil {
			break
		}

		log.Printf("Received frame for module %d", moduleId)
	}
}

func sendFrame(ctx *ClientContext, moduleId uint8, messages []*rpcm.Sequence, timeout time.Duration) error {
	var err error
	endTime := time.Now().Add(timeout)
	frameData := bytes.Buffer{}
	if err = binary.Write(&frameData, binary.BigEndian, moduleId); err != nil {
		return err
	}

	messageBundle := rpcm.NewList(rpcm.RP_TAGS_MESSAGE, rpcm.RPCM_SEQUENCE)
	for _, message := range messages {
		if messageBundle = messageBundle.AddSequence(message); messageBundle == nil {
			return errors.New("Failed to bundle messages")
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
	
	if err := sendData(ctx.conn, finalFrame.Bytes(), endTime); err != nil {
		return err
	}

	return err
}

func recvFrame(ctx *ClientContext, timeout time.Duration) (uint8, *rpcm.List, error) {
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
		return 0, nil, errors.New("Frame size indicated too large or not a multiple of block size")
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
		return 0, nil, err
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
		msgLen, err := conn.Read(buf[receivedLen:])
		receivedLen += uint(msgLen)
		if err != nil {
			break
		}
	}

	if receivedLen == size {
		err = nil
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

		if err != nil {
			return err
		}

		totalSent += nSent
	}

	return err
}

func agentIdFromMessage(message rpcm.MachineSequence) hcp.AgentId {
	var aid hcp.AgentId

	aid.Oid, _ = message[rpcm.RP_TAGS_HCP_SENSOR_ID].(uuid.UUID)
	aid.Iid, _ = message[rpcm.RP_TAGS_HCP_INSTALLER_ID].(uuid.UUID)
	aid.Sid, _ = message[rpcm.RP_TAGS_HCP_SENSOR_ID].(uuid.UUID)
	aid.Architecture, _ = message[rpcm.RP_TAGS_HCP_ARCHITECTURE].(uint32)
	aid.Platform, _ = message[rpcm.RP_TAGS_HCP_PLATFORM].(uint32)

	return aid
}

func sendTimeSync(ctx *ClientContext) error {
	log.Printf( "TODO(maximelb): send time sync message")
	return nil
}