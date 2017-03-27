package rpcm

import (
	"testing"
	"bytes"
	"encoding/json"
	"math/rand"
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
					     AddIpv4(404, 0x01020304).
					     AddIpv6(405, [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}).
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
	list1 := NewList(73, RPCM_RU64)

	seq.AddSequence(72, seq2)
	seq.AddList(74, list1)
	list1.AddInt64(666).AddInt64(777).AddInt64(778).AddInt64(779)
	buf := bytes.Buffer{}
	err := seq.Serialize(&buf)
	if err != nil {
		t.Errorf("Serialize failed.")
	}
	outSeq := NewSequence()
	err = outSeq.Deserialize(&buf)
	if err != nil {
		t.Errorf("Deserialize failed.")
	}
	rawJSON := outSeq.ToJson()
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

	asJSON := outSeq.ToJson()
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
}