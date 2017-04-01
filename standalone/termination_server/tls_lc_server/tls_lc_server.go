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
	"flag"
	"crypto/tls"
	"crypto/rand"
	"github.com/golang/glog"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/lc_server_config"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/lc_server"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/lc_collector"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/rpcm"
	"sync"
	"fmt"
	"net"
	"io"
	"io/ioutil"
	"bytes"
	"github.com/golang/protobuf/proto"
	"encoding/binary"
	"compress/zlib"
	"errors"
	"strconv"
	"os/signal"
	"os"
	"time"
)

const (
	maxInboundFrameSize = 1024*1024*50
	newConnTimeout = 5*time.Second
	idleClientTTL = 120*time.Second
)

// TLSLCServer is an implementation of the LimaCharlie server that uses TLS as a transport.
type TLSLCServer struct {
	IFace string
	Port uint16
	CertFile string
	KeyFile string
	LCConfig *lcServerConfig.Config
	clientsWG sync.WaitGroup
	isDraining bool
	lcServerCtx lcServer.Server
	lcCollectorCtx lcCollector.Collector
}

type tlsClient struct {
	conn net.Conn
	lcClient lcServer.Client
}

func main() {
	port := flag.String("port", "443", "port to listen on")
	iface := flag.String("iface", "0.0.0.0", "interface to listen on")
	configFile := flag.String("conf", "lc_config.pb.txt", "path to config file")
	certFile := flag.String("cert", "c2_cert.pem", "path to the tls cert file in pem format")
	keyFile := flag.String("key", "c2_key.pem", "path to the tls key file in pem format")
	flag.Parse()

	server := TLSLCServer{}
	var (
		configContent []byte
		err error
	)
	if configContent, err = ioutil.ReadFile(*configFile); err != nil {
		glog.Fatalf("failed to load config file: %s", err)
	}

	server.LCConfig = new(lcServerConfig.Config)
	if err = proto.UnmarshalText(string(configContent), server.LCConfig); err != nil {
		glog.Fatalf("failed to parse config file: %s", err)
	}

	server.IFace = *iface
	var num uint64
	if num, err = strconv.ParseUint(*port, 10, 16); err != nil {
		glog.Fatalf("invalid port specified: %s", err)
	}
	server.Port = uint16(num)

	server.CertFile = *certFile
	server.KeyFile = *keyFile

	interruptsChannel := make(chan os.Signal, 1)
	signal.Notify(interruptsChannel, os.Interrupt)
	go func() {
		<-interruptsChannel
		glog.Info("received exiting signal, draining")
		server.isDraining = true
	}()

	if err = server.Run(); err != nil {
		glog.Errorf("server exited with an error: %s", err)
	}

	glog.Info("server exited")
}

func (srv *TLSLCServer) Run() error {
	var err error
	if srv.lcServerCtx, err = lcServer.NewServer(srv.LCConfig); err != nil {
		return err
	}

	srv.lcCollectorCtx = lcCollector.NewStdoutJSON(1, false)
	srv.lcCollectorCtx.SetChannels(srv.lcServerCtx.GetChannels())
	defer srv.lcCollectorCtx.Stop()
	if err := srv.lcCollectorCtx.Start(); err != nil {
		return err
	}

	fullAddrStr := fmt.Sprintf("%s:%d", srv.IFace, srv.Port)

	glog.Infof("starting LC Termination Server on %s with %s/%s", fullAddrStr, srv.CertFile, srv.KeyFile)

	cert, err := tls.LoadX509KeyPair(srv.CertFile, srv.KeyFile)
	if err != nil {
		return err
	}

	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	tlsConfig.Rand = rand.Reader

	resolvedAddr, err := net.ResolveTCPAddr("tcp", fullAddrStr)

	if err != nil {
		return err
	}

	listenSocket, err := net.ListenTCP("tcp", resolvedAddr)
	if err != nil {
		return err
	}

	glog.Infof("listening on %s", fullAddrStr)

	for !srv.isDraining {

		listenSocket.SetDeadline(time.Now().Add(newConnTimeout))
		conn, err := listenSocket.Accept()

		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			return err
		}

		conn = tls.Server(conn, &tlsConfig)

		srv.clientsWG.Add(1)
		go srv.handleClient(conn)
	}

	glog.Info("draining, waiting for clients to exit")
	listenSocket.Close()
	srv.clientsWG.Wait()
	glog.Info("server exiting")

	return nil
}

func (srv *TLSLCServer) Stop() error {
	srv.isDraining = true
	return nil
}

func (srv *TLSLCServer) handleClient(conn net.Conn) {
	defer conn.Close()
	defer srv.clientsWG.Done()

	ctx := new(tlsClient)
	ctx.conn = conn

	// Create a closed function that avoids passing a context around
	sendFunc := func(moduleID uint8, messages []*rpcm.Sequence) error {
		if !srv.isDraining {
			return ctx.sendFrame(moduleID, messages, idleClientTTL)
		}
		return errors.New("draining")
	}

	var err error
	if ctx.lcClient, err = srv.lcServerCtx.NewClient(sendFunc); err != nil {
		return
	}

	defer ctx.lcClient.Stop()

	for !srv.isDraining {
		if moduleID, messages, err := ctx.recvFrame(idleClientTTL); err != nil {
			if err != io.EOF {
				glog.Warningf("%s",err)
			}
			break
		} else if err := ctx.lcClient.ProcessIncoming(moduleID, messages.GetSequence(rpcm.RP_TAGS_MESSAGE)); err != nil {
			glog.Errorf("%s", err)
			break
		}
	}
}

func (c *tlsClient) recvFrame(timeout time.Duration) (uint8, *rpcm.List, error) {
	var (
		err error
		endTime time.Time
		moduleId uint8
		buf []byte
		frameSize uint32
	)

	if timeout != 0 {
		endTime = time.Now().Add(timeout)
	}

	received := rpcm.NewList(rpcm.RP_TAGS_MESSAGE, rpcm.TypeSequence)

	if buf, err = c.recvData(4, endTime); buf == nil || err != nil {
		return 0, nil, err
	}

	if err = binary.Read(bytes.NewBuffer(buf), binary.BigEndian, &frameSize); err != nil {
		return 0, nil, err
	}

	if maxInboundFrameSize < frameSize {
		return 0, nil, errors.New("frame size indicated too large or not a multiple of block size")
	}

	if buf, err = c.recvData(uint(frameSize), endTime); buf == nil || err != nil || len(buf) == 0 {
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
		}
		
		return 0, nil, errors.New("received empty frame")
	}

	if moduleId, err = decompressedBuf.ReadByte(); err != nil {
		return 0, nil, err
	}

	if err = received.Deserialize(&decompressedBuf); err != nil {
		return 0, nil, err
	}

	return moduleId, received, err
}

func (c *tlsClient) sendFrame(moduleId uint8, messages []*rpcm.Sequence, timeout time.Duration) error {
	var err error
	endTime := time.Now().Add(timeout)
	frameData := bytes.Buffer{}
	if err = binary.Write(&frameData, binary.BigEndian, moduleId); err != nil {
		return err
	}

	messageBundle := rpcm.NewList(rpcm.RP_TAGS_MESSAGE, rpcm.TypeSequence)
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

	if err = c.sendData(finalFrame.Bytes(), endTime); err != nil {
		return err
	}

	return nil
}

func (c *tlsClient) recvData(size uint, timeout time.Time) ([]byte, error) {
	buf := make([]byte, size)
	var receivedLen uint

	if !timeout.IsZero() {
		c.conn.SetReadDeadline(timeout)
	}

	for receivedLen < size {
		if msgLen, err := c.conn.Read(buf[receivedLen:]); err != nil {
			return nil, err
		} else if msgLen > 0 {
			receivedLen += uint(msgLen)
		}
	}

	return buf, nil
}

func (c *tlsClient) sendData(buf []byte, timeout time.Time) error {
	if !timeout.IsZero() {
		c.conn.SetWriteDeadline(timeout)
	}

	var totalSent int

	for totalSent < len(buf) {
		if nSent, err := c.conn.Write(buf); err != nil {
			return err
		} else if nSent > 0 {
			totalSent += nSent
		}
	}

	return nil
}