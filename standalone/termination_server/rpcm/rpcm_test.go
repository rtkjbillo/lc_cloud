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

package rpcm

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	//"math/rand"
)

func TestDeepSequence(t *testing.T) {
	tmpBuff := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	seq := NewSequence().AddInt8(66, 42).
		AddInt16(67, 43).
		AddInt32(68, 44).
		AddInt64(69, 45).
		AddStringA(400, "cool").
		AddStringW(401, "story").
		AddBuffer(402, tmpBuff).
		AddTimestamp(403, 999).
		AddIPv4(404, net.ParseIP("127.0.0.1")).
		AddIPv6(405, net.ParseIP("8000:7000:6000:5000:4000:3000:2000:1000")).
		AddPointer32(406, 0xAABBCCDD).
		AddPointer64(407, 0xAABBCCDD01020304).
		AddTimestamp(403, 666)
	seq2 := NewSequence().AddInt8(70, 46).
		AddInt16(71, 47).
		AddPointer32(406, 0xAABBCCDD).
		AddPointer64(407, 0xAABBCCDD01020304).
		AddTimestamp(403, 666).
		AddStringA(400, "another").
		AddStringW(401, "bro")
	list1 := NewList(73, TypeInt64)

	seq.AddSequence(72, seq2)
	seq.AddList(74, list1)
	list1.AddInt64(666).AddInt64(777).AddInt64(778).AddInt64(779)
	buf := bytes.Buffer{}
	err := seq.Serialize(&buf)
	if err != nil {
		t.Errorf("Serialize failed: %s.", err)
	}
	outSeq := NewSequence()
	err = outSeq.Deserialize(&buf)
	if err != nil {
		t.Errorf("Deserialize failed: %s.", err)
	}
	rawJSON := outSeq.ToJSON()
	jsonString, err := json.Marshal(rawJSON)
	if err != nil || jsonString == nil {
		t.Errorf(err.Error())
	}

	if test8, ok := seq.GetInt8(66); !ok || test8 != 42 {
		t.Errorf("Failed to Get value.")
	}
	if test16, ok := seq.GetInt16(67); !ok || test16 != 43 {
		t.Errorf("Failed to Get value.")
	}
	if test32, ok := seq.GetInt32(68); !ok || test32 != 44 {
		t.Errorf("Failed to Get value.")
	}
	if test64, ok := seq.GetInt64(69); !ok || test64 != 45 {
		t.Errorf("Failed to Get value.")
	}
	if testA, ok := seq.GetStringA(400); !ok || testA != "cool" {
		t.Errorf("Failed to Get value.")
	}
	if testW, ok := seq.GetStringW(401); !ok || testW != "story" {
		t.Errorf("Failed to Get value.")
	}
	if testBuffer, ok := seq.GetBuffer(402); !ok || len(testBuffer) != len(tmpBuff) {
		t.Errorf("Failed to Get value.")
	}
	if testSeq, ok := seq.GetSequence(72); ok {
		if test8, ok := testSeq.GetInt8(70); !ok || test8 != 46 {
			t.Errorf("Failed to Get value.")
		}
	} else {
		t.Errorf("Failed to Get value.")
	}
}

/*
func getRandomBuffer(minSize int, maxSize int) []byte {
	buf := make([]byte, minSize + rand.Intn(maxSize - minSize))
	for i := range buf {
		buf[ i ] = byte(rand.Intn(256))
	}
	return buf
}

func TestNaming(t *testing.T) {
	seq := NewSequence().AddInt8(RP_TAGS_HOST_NAME, 6).
			    		 AddStringA(RP_TAGS_ACCESS_TIME, "99")

	buf := bytes.Buffer{}
	err := seq.Serialize(&buf)

	outSeq := NewSequence()
	err = outSeq.Deserialize(&buf)
	if err != nil {
		t.Errorf("Deserialize failed.")
	}

	asMachine := outSeq.ToMachine()
	if asMachine == nil {
		t.Error("ToMachine failed.")
	}
	if val, ok := asMachine[RP_TAGS_HOST_NAME]; !ok || val != uint8(6) {
		t.Error("Expected RP_TAGS_HOST_NAME in ToMachine output with value 6.")
	}
	if val, ok := asMachine[RP_TAGS_ACCESS_TIME]; !ok || val != "99" {
		t.Error("Expected RP_TAGS_ACCESS_TIME in ToMachine output with value 99.")
	}

	asJSON := outSeq.ToJSON()
	if asJSON == nil {
		t.Error("ToMachine failed.")
	}
	if val, ok := asJSON["base.HOST_NAME"]; !ok || val != uint8(6) {
		t.Error(asJSON)
		t.Error("Expected base.HOST_NAME in ToJson output with value 6.")
	}
	if val, ok := asJSON["base.ACCESS_TIME"]; !ok || val != "99" {
		t.Error("Expected base.ACCESS_TIME in ToJson output with value 99.")
	}
}

func TestFuzz(t *testing.T) {
	for i := 1; i <= 1000; i++ {
		randBuf := getRandomBuffer(1, 2048)
		outSeq := NewSequence()
		err := outSeq.Deserialize(bytes.NewBuffer(randBuf))
		if err == nil {
			t.Error("Got a valid structure out of random fuzz data, unexpected.")
		}
	}
}*/
