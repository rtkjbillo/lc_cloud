package rpcm

import (
	"testing"
	"bytes"
	"encoding/json"
)

func TestSequence(t *testing.T) {
	seq := Sequence().AddInt8(66, 42).AddInt16(67, 43).AddInt32(68, 44).AddInt64(69, 45)
	buf := bytes.Buffer{}
	err := seq.Serialize(&buf)
	if err != nil {
		t.Errorf("Serialize failed.")
	}
	outSeq := Sequence()
	err = outSeq.Deserialize(&buf)
	if err != nil {
		t.Errorf("Deserialize failed.")
	}
	rawJson := outSeq.ToJson()
	jsonString, err := json.Marshal(rawJson)
	if err != nil {
		t.Errorf(err.Error())
	}
	t.Log(string(jsonString))
}

func TestDeepSequence(t *testing.T) {
	seq := Sequence().AddInt8(66, 42).AddInt16(67, 43).AddInt32(68, 44).AddInt64(69, 45)
	seq2 := Sequence().AddInt8(70, 46).AddInt16(71, 47)
	list1 := List(73, RPCM_RU64)

	seq.AddSequence(72, seq2)
	seq.AddList(74, list1)
	list1.AddInt64(666).AddInt64(777).AddInt64(778).AddInt64(779)
	buf := bytes.Buffer{}
	err := seq.Serialize(&buf)
	if err != nil {
		t.Errorf("Serialize failed.")
	}
	outSeq := Sequence()
	err = outSeq.Deserialize(&buf)
	if err != nil {
		t.Errorf("Deserialize failed.")
	}
	rawJson := outSeq.ToJson()
	jsonString, err := json.Marshal(rawJson)
	if err != nil {
		t.Errorf(err.Error())
	}
	t.Log(string(jsonString))
}