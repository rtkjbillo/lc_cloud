package rpcm

import (
	"testing"
	"bytes"
	"encoding/json"
)

func TestBasic(t *testing.T) {
	seq := Sequence()
	seq.AddInt8(66, 42)
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