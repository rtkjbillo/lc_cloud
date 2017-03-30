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
	"os/signal"
	"flag"
	"crypto/tls"
	"crypto/rand"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/lc_server"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/rpcm"
	"github.com/refractionPOINT/lc_cloud/standalone/termination_server/utils"
	"sync"
	"net"
	"io"
	"io/ioutil"
	"bytes"
	"compress/zlib"
)

type TLSLCServer struct {
	IFace string
	Port uint16
	CertFile string
	KeyFile string
	IsDebug bool
	LCConfig LcServerConfig
	activeClients sync.WaitGroup
	isDraining bool
	lcServerCtx *lcServer.Server
}

type tlsClient struct {
	conn net.Conn
	lcClient *lcServer.Client
}

func (srv *TLSLCServer) Start() error {
	var err error
	srv.lcServerCtx, err = lcServer.NewServer(nil)
	fullAddrStr := fmt.Sprintf("%s:%d", srv.IFace, srv.Port)

	glog.Info("starting LC Termination Server on %s with %s/%s", fullAddrStr, srv.CertFile, srv.KeyFile)

	srv.lcServerCtx = new(lcServer.Server)

	cert, err := tls.LoadX509KeyPair(srv.certFile, srv.keyFile)
	if err != nil {
		glog.Errorf("failed to load cert and key: %s", err)
		return err
	}

	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	tlsConfig.Rand = rand.Reader

	resolvedAddr, err := net.ResolveTCPAddr("tcp", fullAddrStr)

	if err != nil {
		glog.Errorf("failed to resolve listen address: %s", err)
		return err
	}

	listenSocket, err := net.ListenTCP("tcp", resolvedAddr)
	if err != nil {
		glog.Errorf("could not open %s for listening: %s", fullAddrStr, err)
		return err
	}

	glog.Infof("listening on %s", fullAddrStr)

	for !srv.isDraining {

		listenSocket.SetDeadline(time.Now().Add(5 * time.Second))
		conn, err := listenSocket.Accept()

		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			glog.Errorf("error accepting on socket: %s", err)
			return err
		}

		conn = tls.Server(conn, &tlsConfig)

		srv.activeClients.Add(1)
		go srv.handleClient(conn)
	}

	glog.Info("draining, waiting for clients to exit")
	listenSocket.Close()
	srv.activeClients.Wait()
	glog.Info("server exiting")
}

func (srv *TLSLCServer) Stop() error {

}

func (srv *TLSLCServer) handleClient(conn net.Conn) {
	defer conn.Close()
	defer srv.activeClients.Done()

	ctx := new(tlsClient)
	ctx.conn = conn

	sendFunc := func(moduleID uint8, messages []*rpcm.Sequence) error {
		if !ctx.srv.isDraining {
			return ctx.sendFrame(moduleID, messages, 120*time.Second)
		}
		return errors.New("draining")
	}

	ctx.lcClient = srv.lcServerCtx.NewClient(sendFunc)
	defer ctx.lcClient.Close()

	for !srv.isDraining {
		if moduleID, messages, err := ctx.recvFrame(120*time.Second); err != nil {
			break
		} else if err := ctx.lcClient.Receive(moduleID, messages.GetSequence(rpcm.RP_TAGS_MESSAGE)); err != nil {
			break
		}
	}
}

func (c *tlsClient) recvFrame(timeout time.Duration) (uint8, *rpcm.List, error) {
	var err error
	var endTime time.Time
	var moduleId uint8
	var buf []byte
	var frameSize uint32

	if timeout != 0 {
		endTime = time.Now().Add(timeout)
	}

	received := rpcm.NewList(rpcm.RP_TAGS_MESSAGE, rpcm.RPCM_SEQUENCE)

	if buf, err = recvData(c.conn, 4, endTime); buf == nil || err != nil {
		return 0, nil, err
	}

	if err = binary.Read(bytes.NewBuffer(buf), binary.BigEndian, &frameSize); err != nil {
		return 0, nil, err
	}

	if MAX_INBOUND_FRAME_SIZE < frameSize {
		return 0, nil, errors.New("frame size indicated too large or not a multiple of block size")
	}

	if buf, err = recvData(c.conn, uint(frameSize), endTime); buf == nil || err != nil || len(buf) == 0 {
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

func (c *tlsClient) sendFrame(moduleId uint8, messages []*rpcm.Sequence, timeout time.Duration) error {
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

	if err = sendData(c.conn, finalFrame.Bytes(), endTime); err != nil {
		return err
	}

	return err
}

func (c *tlsClient) recvData(size uint, timeout time.Time) ([]byte, error) {
	buf := make([]byte, size)
	var receivedLen uint
	var err error

	if !timeout.IsZero() {
		c.conn.SetReadDeadline(timeout)
	}

	for receivedLen < size {
		msgLen := 0
		msgLen, err = c.conn.Read(buf[receivedLen:])
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

func (c *tlsClient) sendData(buf []byte, timeout time.Time) error {
	var err error

	if !timeout.IsZero() {
		c.conn.SetWriteDeadline(timeout)
	}

	var totalSent int

	for totalSent < len(buf) {
		nSent, err := c.conn.Write(buf)

		if nSent > 0 {
			totalSent += nSent
		}

		if err != nil {
			return err
		}
	}

	return err
}