// Copyright 2015 refractionPOINT
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use e file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package rpcm provides an interface to serialize, deserialize and generally
manipulate RPCommonMessages that are used by LimaCharlie.

The messages are analogous to JSON where every element has a Type and a Tag.

The basic building blocks in RPCM are the Sequence and the List.

The Sequence is a dictionary where only one element with a certain Tag (the key) is
present regardless of the Type and value of that element.

The List is an array of elements where ALL elements have the same Tag and Type.

Sequences and Lists can be embedded into each other at will.

Messages are serialized with Tags as UINT32, the mapping to a human readable format
is done when necessary using a machine-generated "header" from a source JSON file used
as a ground truth Uint32<-->Str between the various programming languages supported.
*/
package rpcm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
)

// Data type values supported in RPCM
const (
	TypeInvalid  = 0
	TypeRu8           = 1
	TypeRu16          = 2
	TypeRu32          = 3
	TypeRu64          = 4
	TypeStringA       = 5
	TypeStringW       = 6
	TypeBuffer        = 7
	TypeTimestamp     = 8
	TypeIPv4          = 9
	TypeIPv6          = 10
	TypePointer32    = 11
	TypePointer64    = 12
	TypeTimedelta     = 13
	TypeComplexTypes = 0x80
	TypeSequence      = 0x81
	TypeList          = 0x82
)

type rpcmElement interface {
	GetType() byte
	GetValue() interface{}
	serialize(toBuf *bytes.Buffer) error
}

type rElem struct {
	typ uint8
}

type ru8 struct {
	rElem
	value uint8
}

type ru16 struct {
	rElem
	value uint16
}

type ru32 struct {
	rElem
	value uint32
}

type ru64 struct {
	rElem
	value uint64
}

type rStringA struct {
	rElem
	value string
}

type rStringW struct {
	rElem
	value string
}

type rBuffer struct {
	rElem
	value []byte
}

type rTimestamp struct {
	rElem
	value uint64
}

type rIPv4 struct {
	rElem
	value net.IP
}

type rIPv6 struct {
	rElem
	value net.IP
}

type rPointer32 struct {
	rElem
	value uint32
}

type rPointer64 struct {
	rElem
	value uint64
}

type rTimedelta struct {
	rElem
	value uint64
}

type Sequence struct {
	rElem
	elements map[uint32]rpcmElement
}

type List struct {
	rElem
	elemTag  uint32
	elemType uint8
	elements []rpcmElement
}

// MachineSequence is a native Go representation of a Sequence
type MachineSequence map[uint32]interface{}

// MachineList is a native Go representation of a List
type MachineList []interface{}

func (e *rElem) GetType() uint8 {
	return e.typ
}

func (e *ru8) GetValue() interface{} {
	return e.value
}

func (e *ru16) GetValue() interface{} {
	return e.value
}

func (e *ru32) GetValue() interface{} {
	return e.value
}

func (e *ru64) GetValue() interface{} {
	return e.value
}

func (e *rStringA) GetValue() interface{} {
	return e.value
}

func (e *rStringW) GetValue() interface{} {
	return e.value
}

func (e *rBuffer) GetValue() interface{} {
	return e.value
}

func (e *rTimestamp) GetValue() interface{} {
	return e.value
}

func (e *rIPv4) GetValue() interface{} {
	return e.value
}

func (e *rIPv6) GetValue() interface{} {
	return e.value
}

func (e *rPointer32) GetValue() interface{} {
	return e.value
}

func (e *rPointer64) GetValue() interface{} {
	return e.value
}

func (e *rTimedelta) GetValue() interface{} {
	return e.value
}

// Sequence is a set of (Tag, Type, Value) tuples where Tag is guaranteed to be unique
func (e *Sequence) GetValue() interface{} {
	return e.elements
}

// List is a list of (Tag, Type, Value) tuples where all tuples are guaranteed to have
// the same Tag and Type
func (e *List) GetValue() interface{} {
	return e.elements
}

//=============================================================================
// Constructors
//=============================================================================

// NewSequence creates a new blank Sequence
func NewSequence() *Sequence {
	return &Sequence{rElem: rElem{TypeSequence}, elements: make(map[uint32]rpcmElement)}
}


// NewList creates a new blank list of elemTag and elemType items
func NewList(elemTag uint32, elemType uint8) *List {
	return &List{rElem: rElem{TypeList}, elemTag: elemTag, elemType: elemType}
}

//=============================================================================
// Serialize
//=============================================================================

func (e *ru8) serialize(toBuf *bytes.Buffer) error {
	return toBuf.WriteByte(e.value)
}

func (e *ru16) serialize(toBuf *bytes.Buffer) error {
	return binary.Write(toBuf, binary.BigEndian, e.value)
}

func (e *ru32) serialize(toBuf *bytes.Buffer) error {
	return binary.Write(toBuf, binary.BigEndian, e.value)
}

func (e *ru64) serialize(toBuf *bytes.Buffer) error {
	return binary.Write(toBuf, binary.BigEndian, e.value)
}

func (e *rStringA) serialize(toBuf *bytes.Buffer) error {
	err := binary.Write(toBuf, binary.BigEndian, uint32(len(e.value)+1))
	if err != nil {
		return err
	}
	_, err = toBuf.Write([]byte(e.value))
	if err != nil {
		return err
	}
	err = toBuf.WriteByte(0)
	if err != nil {
		return err
	}

	return nil
}

func (e *rStringW) serialize(toBuf *bytes.Buffer) error {
	err := binary.Write(toBuf, binary.BigEndian, uint32(len(e.value)+1))
	if err != nil {
		return err
	}
	_, err = toBuf.Write([]byte(e.value))
	if err != nil {
		return err
	}
	err = toBuf.WriteByte(0)
	if err != nil {
		return err
	}

	return nil
}

func (e *rBuffer) serialize(toBuf *bytes.Buffer) error {
	err := binary.Write(toBuf, binary.BigEndian, uint32(len(e.value)))
	if err != nil {
		return err
	}
	_, err = toBuf.Write(e.value)
	if err != nil {
		return err
	}

	return nil
}

func (e *rTimestamp) serialize(toBuf *bytes.Buffer) error {
	return binary.Write(toBuf, binary.BigEndian, e.value)
}

func (e *rIPv4) serialize(toBuf *bytes.Buffer) error {
	_, err := toBuf.Write(e.value.To4())
	return err
}

func (e *rIPv6) serialize(toBuf *bytes.Buffer) error {
	_, err := toBuf.Write(e.value.To16())
	return err
}

func (e *rPointer32) serialize(toBuf *bytes.Buffer) error {
	return binary.Write(toBuf, binary.BigEndian, e.value)
}

func (e *rPointer64) serialize(toBuf *bytes.Buffer) error {
	return binary.Write(toBuf, binary.BigEndian, e.value)
}

func (e *rTimedelta) serialize(toBuf *bytes.Buffer) error {
	return binary.Write(toBuf, binary.BigEndian, e.value)
}

// Serialize convertts the Sequence structure in a slice of bytes that can be used
// to restore the original Sequence regardless of the platform.
func (e *Sequence) Serialize(toBuf *bytes.Buffer) error {
    return e.serialize(toBuf)
}

func (e *Sequence) serialize(toBuf *bytes.Buffer) error {
	err := binary.Write(toBuf, binary.BigEndian, uint32(len(e.elements)))
	if err != nil {
		return err
	}
	for tag, elem := range e.elements {
		err = binary.Write(toBuf, binary.BigEndian, tag)
		if err != nil {
			return err
		}
		err = binary.Write(toBuf, binary.BigEndian, elem.GetType())
		if err != nil {
			return err
		}
		err = elem.serialize(toBuf)
		if err != nil {
			return err
		}
	}
	return nil
}

// Serialize convertts the List structure in a slice of bytes that can be used
// to restore the original List regardless of the platform.
func (e *List) Serialize(toBuf *bytes.Buffer) error {
    return e.serialize(toBuf)
}

func (e *List) serialize(toBuf *bytes.Buffer) error {
	err := binary.Write(toBuf, binary.BigEndian, e.elemTag)
	if err != nil {
		return err
	}
	err = binary.Write(toBuf, binary.BigEndian, e.elemType)
	if err != nil {
		return err
	}
	err = binary.Write(toBuf, binary.BigEndian, uint32(len(e.elements)))
	if err != nil {
		return err
	}
	for _, elem := range e.elements {
		if e.elemType != elem.GetType() {
			return errors.New("sanity failure: list contains unexpected type")
		}
		err = binary.Write(toBuf, binary.BigEndian, e.elemTag)
		if err != nil {
			return err
		}
		err = binary.Write(toBuf, binary.BigEndian, e.elemType)
		if err != nil {
			return err
		}
		err = elem.serialize(toBuf)
		if err != nil {
			return err
		}
	}
	return nil
}

//=============================================================================
// Deserialize
//=============================================================================

// Deserialize a slice of bytes into the Sequence it represents.
func (e *Sequence) Deserialize(fromBuf *bytes.Buffer) error {
	var nElements uint32
	var tag uint32
	var typ uint8
	var err error

	e.typ = TypeSequence

	err = binary.Read(fromBuf, binary.BigEndian, &nElements)
	if err != nil {
		return err
	}

	for i := uint32(0); i < nElements; i++ {
		var tmpElem rpcmElement

		err = binary.Read(fromBuf, binary.BigEndian, &tag)
		if err != nil {
			return err
		}
		err = binary.Read(fromBuf, binary.BigEndian, &typ)
		if err != nil {
			return err
		}
		tmpElem, err = rpcmDeserializeElem(fromBuf, typ)
		if tmpElem == nil || err != nil {
			return errors.New("failed to deserialize an element")
		}

		e.elements[tag] = tmpElem
	}

	return err
}

// Deserialize a slice of bytes into the List it represents.
func (e *List) Deserialize(fromBuf *bytes.Buffer) error {
	var nElements uint32
	var tag uint32
	var typ uint8
	var err error

	e.typ = TypeList

	err = binary.Read(fromBuf, binary.BigEndian, &e.elemTag)
	if err != nil {
		return err
	}

	err = binary.Read(fromBuf, binary.BigEndian, &e.elemType)
	if err != nil {
		return err
	}

	err = binary.Read(fromBuf, binary.BigEndian, &nElements)
	if err != nil {
		return err
	}

	for i := uint32(0); i < nElements; i++ {
		var tmpElem rpcmElement

		err = binary.Read(fromBuf, binary.BigEndian, &tag)
		if err != nil {
			return err
		}
		if tag != e.elemTag {
			return errors.New("sanity failure: element tag in list does not match")
		}
		err = binary.Read(fromBuf, binary.BigEndian, &typ)
		if err != nil {
			return err
		}
		if typ != e.elemType {
			return errors.New("sanity failure: element type in list does not match")
		}
		tmpElem, err = rpcmDeserializeElem(fromBuf, typ)
		if tmpElem == nil || err != nil {
			return errors.New("failed to deserialize an element")
		}

		e.elements = append(e.elements, tmpElem)
	}

	return err
}

func rpcmDeserializeElem(fromBuf *bytes.Buffer, typ uint8) (rpcmElement, error) {
	var elem rpcmElement
	var elemLen uint32
	var tmpBuf []byte
	var err error
	var sizeRead int

	switch typ {
	case TypeRu8:
		elem = &ru8{rElem: rElem{typ: typ}}
		err = binary.Read(fromBuf, binary.BigEndian, &elem.(*ru8).value)
	case TypeRu16:
		elem = &ru16{rElem: rElem{typ: typ}}
		err = binary.Read(fromBuf, binary.BigEndian, &elem.(*ru16).value)
	case TypeRu32:
		elem = &ru32{rElem: rElem{typ: typ}}
		err = binary.Read(fromBuf, binary.BigEndian, &elem.(*ru32).value)
	case TypeRu64:
		elem = &ru64{rElem: rElem{typ: typ}}
		err = binary.Read(fromBuf, binary.BigEndian, &elem.(*ru64).value)
	case TypeStringA:
		elem = &rStringA{rElem: rElem{typ: TypeStringA}}
		err = binary.Read(fromBuf, binary.BigEndian, &elemLen)
		if uint32(fromBuf.Len()) < elemLen || elemLen == 0 {
			err = errors.New("not enough data in buffer")
		} else {
			tmpBuf = make([]byte, elemLen)
			sizeRead, err = fromBuf.Read(tmpBuf)
			if uint32(sizeRead) != elemLen {
				err = errors.New("error reading enough data from buffer")
			}
		}
		if err == nil {
			elem.(*rStringA).value = string(tmpBuf)
			if elem.(*rStringA).value[len(elem.(*rStringA).value)-1] == 0 {
				elem.(*rStringA).value = elem.(*rStringA).value[0 : len(elem.(*rStringA).value)-1]
			}
		}
	case TypeStringW:
		elem = &rStringW{rElem: rElem{typ: typ}}
		err = binary.Read(fromBuf, binary.BigEndian, &elemLen)
		if uint32(fromBuf.Len()) < elemLen || elemLen == 0 {
			err = errors.New("Not enough data in buffer")
		} else {
			tmpBuf = make([]byte, elemLen)
			sizeRead, err = fromBuf.Read(tmpBuf)
			if uint32(sizeRead) != elemLen {
				err = errors.New("Error reading enough data from buffer")
			}
		}
		if err == nil {
			elem.(*rStringW).value = string(tmpBuf)
			if elem.(*rStringW).value[len(elem.(*rStringW).value)-1] == 0 {
				elem.(*rStringW).value = elem.(*rStringW).value[0 : len(elem.(*rStringW).value)-1]
			}
		}
	case TypeBuffer:
		elem = &rBuffer{rElem: rElem{typ: typ}}
		err = binary.Read(fromBuf, binary.BigEndian, &elemLen)
		if uint32(fromBuf.Len()) < elemLen || elemLen == 0 {
			err = errors.New("Not enough data in buffer")
		} else {
			tmpBuf = make([]byte, elemLen)
			sizeRead, err = fromBuf.Read(tmpBuf)
			if uint32(sizeRead) != elemLen {
				err = errors.New("Error reading enough data from buffer")
			}
		}
		if err == nil {
			elem.(*rBuffer).value = tmpBuf
		}
	case TypeTimestamp:
		elem = &rTimestamp{rElem: rElem{typ: typ}}
		err = binary.Read(fromBuf, binary.BigEndian, &elem.(*rTimestamp).value)
	case TypeIPv4:
		elem = &rIPv4{rElem: rElem{typ: typ}}
		var tmpVal uint32
		if err = binary.Read(fromBuf, binary.BigEndian, &tmpVal); err == nil {
			binary.BigEndian.PutUint32(elem.(*rIPv4).value, tmpVal)
		}
	case TypeIPv6:
		elem = &rIPv6{rElem: rElem{typ: typ}}
		tmpVal := make([]byte, 16)
		if sizeRead, err = fromBuf.Read(tmpVal); err != nil || uint32(sizeRead) != 16 {
			err = errors.New("Error reading enough data from buffer")
		}
		copy(elem.(*rIPv6).value, tmpVal)
	case TypePointer32:
		elem = &rPointer32{rElem: rElem{typ: typ}}
		err = binary.Read(fromBuf, binary.BigEndian, &elem.(*rPointer32).value)
	case TypePointer64:
		elem = &rPointer64{rElem: rElem{typ: typ}}
		err = binary.Read(fromBuf, binary.BigEndian, &elem.(*rPointer64).value)
	case TypeTimedelta:
		elem = &rTimedelta{rElem: rElem{typ: typ}}
		err = binary.Read(fromBuf, binary.BigEndian, &elem.(*rTimedelta).value)
	case TypeSequence:
		elem = &Sequence{rElem: rElem{typ: typ}, elements: make(map[uint32]rpcmElement)}
		err = elem.(*Sequence).Deserialize(fromBuf)
	case TypeList:
		elem = &List{rElem: rElem{typ: typ}}
		err = elem.(*List).Deserialize(fromBuf)
	default:
		elem = nil
	}

	if err != nil {
		elem = nil
	}

	return elem, err
}

//=============================================================================
// Format Change
//=============================================================================

// ToMachine takes a Sequence and turns it into a native Go structure of slices and maps.
func (e *Sequence) ToMachine() MachineSequence {
	j := make(map[uint32]interface{})

	for tag, val := range e.elements {
		if val.GetType() == TypeSequence {
			j[tag] = val.(*Sequence).ToMachine()
		} else if val.GetType() == TypeList {
			j[tag] = val.(*List).ToMachine()
		} else {
			j[tag] = val.GetValue()
		}
	}

	return j
}

// ToMachine takes a List and turns it into a native Go structure of slices and maps.
func (e *List) ToMachine() MachineList {
	j := make([]interface{}, 0)

	for _, val := range e.elements {
		if val.GetType() == TypeSequence {
			j = append(j, val.(*Sequence).ToMachine())
		} else if val.GetType() == TypeList {
			j = append(j, val.(*List).ToMachine())
		} else {
			j = append(j, val.GetValue())
		}
	}

	return j
}

// ToJSON takes a Sequence and turns it into the JSON compatible format.
func (e *Sequence) ToJSON() map[string]interface{} {
	var tagLabel string
	var ok bool

	j := make(map[string]interface{})

	for tag, val := range e.elements {
		if tagLabel, ok = HumanReadableTags[tag]; !ok {
			tagLabel = strconv.FormatUint(uint64(tag), 16)
		}

		if val.GetType() == TypeSequence {
			j[tagLabel] = val.(*Sequence).ToJSON()
		} else if val.GetType() == TypeList {
			j[tagLabel] = val.(*List).ToJSON()
		} else {
			j[tagLabel] = val.GetValue()
		}
	}

	return j
}

// ToJSON takes a List and turns it into the JSON compatible format.
func (e *List) ToJSON() []interface{} {
	j := make([]interface{}, 0)

	for _, val := range e.elements {
		if val.GetType() == TypeSequence {
			j = append(j, val.(*Sequence).ToJSON())
		} else if val.GetType() == TypeList {
			j = append(j, val.(*List).ToJSON())
		} else {
			j = append(j, val.GetValue())
		}
	}

	return j
}

//=============================================================================
// Sequence
//=============================================================================

// AddInt8 adds an 8 bit unsigned integer with the specified tag to the Sequence.
func (e *Sequence) AddInt8(tag uint32, number uint8) *Sequence {
	e.elements[tag] = &ru8{rElem: rElem{typ: TypeRu8}, value: number}
	return e
}

// AddInt16 adds an 16 bit unsigned integer with the specified tag to the Sequence.
func (e *Sequence) AddInt16(tag uint32, number uint16) *Sequence {
	e.elements[tag] = &ru16{rElem: rElem{typ: TypeRu16}, value: number}
	return e
}

// AddInt32 adds an 32 bit unsigned integer with the specified tag to the Sequence.
func (e *Sequence) AddInt32(tag uint32, number uint32) *Sequence {
	e.elements[tag] = &ru32{rElem: rElem{typ: TypeRu32}, value: number}
	return e
}

// AddInt64 adds an 64 bit unsigned integer with the specified tag to the Sequence.
func (e *Sequence) AddInt64(tag uint32, number uint64) *Sequence {
	e.elements[tag] = &ru64{rElem: rElem{typ: TypeRu64}, value: number}
	return e
}

// AddStringA adds a ascii string with the specified tag to the Sequence.
func (e *Sequence) AddStringA(tag uint32, str string) *Sequence {
	e.elements[tag] = &rStringA{rElem: rElem{typ: TypeStringA}, value: str}
	return e
}

// AddStringW adds a wide character string with the specified tag to the Sequence.
func (e *Sequence) AddStringW(tag uint32, str string) *Sequence {
	e.elements[tag] = &rStringW{rElem: rElem{typ: TypeStringW}, value: str}
	return e
}

// AddBuffer adds a buffer with the specified tag to the Sequence.
func (e *Sequence) AddBuffer(tag uint32, buf []byte) *Sequence {
	e.elements[tag] = &rBuffer{rElem: rElem{typ: TypeBuffer}, value: buf}
	return e
}

// AddTimestamp adds a 64 bit timestamp with the specified tag to the Sequence.
func (e *Sequence) AddTimestamp(tag uint32, ts uint64) *Sequence {
	e.elements[tag] = &rTimestamp{rElem: rElem{typ: TypeTimestamp}, value: ts}
	return e
}

// AddIPv4 adds an IP v4 with the specified tag to the Sequence.
func (e *Sequence) AddIPv4(tag uint32, ip4 net.IP) *Sequence {
	e.elements[tag] = &rIPv4{rElem: rElem{typ: TypeIPv4}, value: ip4.To4()}
	return e
}

// AddIPv6 adds an IP v6 with the specified tag to the Sequence.
func (e *Sequence) AddIPv6(tag uint32, ip6 net.IP) *Sequence {
	e.elements[tag] = &rIPv6{rElem: rElem{typ: TypeIPv6}, value: ip6.To16()}
	return e
}

// AddPointer32 adds a 32 bit pointer with the specified tag to the Sequence.
func (e *Sequence) AddPointer32(tag uint32, ptr uint32) *Sequence {
	e.elements[tag] = &rPointer32{rElem: rElem{typ: TypePointer32}, value: ptr}
	return e
}

// AddPointer64 adds a 64 bit pointer with the specified tag to the Sequence.
func (e *Sequence) AddPointer64(tag uint32, ptr uint64) *Sequence {
	e.elements[tag] = &rPointer64{rElem: rElem{typ: TypePointer64}, value: ptr}
	return e
}

// AddTimedelta adds a time delta with the specified tag to the Sequence.
func (e *Sequence) AddTimedelta(tag uint32, td uint64) *Sequence {
	e.elements[tag] = &rTimedelta{rElem: rElem{typ: TypeTimedelta}, value: td}
	return e
}

// AddSequence adds a Sequence with the specified tag to the Sequence.
func (e *Sequence) AddSequence(tag uint32, seq *Sequence) *Sequence {
	seq.typ = TypeSequence
	e.elements[tag] = seq
	return e
}

// AddList adds a List with the specified tag to the Sequence.
func (e *Sequence) AddList(tag uint32, list *List) *Sequence {
	list.typ = TypeList
	e.elements[tag] = list
	return e
}

// GetInt8 returns an 8 bit unsigned integer with the specific tag, if present.
func (e *Sequence) GetInt8(tag uint32) (uint8, bool) {
	if elem, found := e.elements[tag]; found && elem.GetType() == TypeRu8 {
		return  elem.(*ru8).value, true
	}

	return 0, false
}

// GetInt16 returns an 16 bit unsigned integer with the specific tag, if present.
func (e *Sequence) GetInt16(tag uint32) (uint16, bool) {
	if elem, found := e.elements[tag]; found && elem.GetType() == TypeRu16 {
		return elem.(*ru16).value, true
	}

	return 0, false
}

// GetInt32 returns an 32 bit unsigned integer with the specific tag, if present.
func (e *Sequence) GetInt32(tag uint32) (uint32, bool) {
	if elem, found := e.elements[tag]; found && elem.GetType() == TypeRu32 {
		return elem.(*ru32).value, true
	}

	return 0, false
}

// GetInt64 returns an 64 bit unsigned integer with the specific tag, if present.
func (e *Sequence) GetInt64(tag uint32) (uint64, bool) {
	if elem, found := e.elements[tag]; found && elem.GetType() == TypeRu64 {
		return elem.(*ru64).value, true
	}

	return 0, false
}

// GetStringA returns an ascii string with the specific tag, if present.
func (e *Sequence) GetStringA(tag uint32) (string, bool) {
	if elem, found := e.elements[tag]; found && elem.GetType() == TypeStringA {
		return elem.(*rStringA).value, true
	}

	return "", false
}

// GetStringW returns a wide character string with the specific tag, if present.
func (e *Sequence) GetStringW(tag uint32) (string, bool) {
	if elem, found := e.elements[tag]; found && elem.GetType() == TypeStringW {
		return elem.(*rStringW).value, true
	}

	return "", false
}

// GetBuffer returns a buffer with the specific tag, if present.
func (e *Sequence) GetBuffer(tag uint32) ([]byte, bool) {
	if elem, found := e.elements[tag]; found && elem.GetType() == TypeBuffer {
		return elem.(*rBuffer).value, true
	}

	return []byte{}, false
}

// GetTimestamp returns a timestamp with the specific tag, if present.
func (e *Sequence) GetTimestamp(tag uint32) (uint64, bool) {
	if elem, found := e.elements[tag]; found && elem.GetType() == TypeTimestamp {
		return elem.(*rTimestamp).value, true
	}

	return 0, false
}

// GetIPv4 returns an IP v4 with the specific tag, if present.
func (e *Sequence) GetIPv4(tag uint32) (net.IP, bool) {
	if elem, found := e.elements[tag]; found && elem.GetType() == TypeIPv4 {
		return elem.(*rIPv4).value.To4(), true
	}

	return net.IP{}, false
}

// GetIPv6 returns an IP v6 with the specific tag, if present.
func (e *Sequence) GetIPv6(tag uint32) (net.IP, bool) {
	if elem, found := e.elements[tag]; found && elem.GetType() == TypeIPv6 {
		return elem.(*rIPv6).value.To16(), true
	}

	return net.IP{}, false
}

// GetPointer32 returns a 32 bit pointer with the specific tag, if present.
func (e *Sequence) GetPointer32(tag uint32) (uint32, bool) {
	if elem, found := e.elements[tag]; found && elem.GetType() == TypePointer32 {
		return elem.(*rPointer32).value, true
	}

	return 0, false
}

// GetPointer64 returns a 64 bit pointer with the specific tag, if present.
func (e *Sequence) GetPointer64(tag uint32) (uint64, bool) {
	if elem, found := e.elements[tag]; found && elem.GetType() == TypePointer64 {
		return elem.(*rPointer64).value, true
	}

	return 0, false
}

// GetTimedelta returns a time delta with the specific tag, if present.
func (e *Sequence) GetTimedelta(tag uint32) (uint64, bool) {
	if elem, found := e.elements[tag]; found && elem.GetType() == TypeTimedelta {
		return elem.(*rTimedelta).value, true
	}

	return 0, false
}

// GetSequence returns a Sequence with the specific tag, if present.
func (e *Sequence) GetSequence(tag uint32) (*Sequence, bool) {
	if elem, found := e.elements[tag]; found && elem.GetType() == TypeSequence {
		return elem.(*Sequence), true
	}

	return nil, false
}

// GetList returns a List with the specific tag, if present.
func (e *Sequence) GetList(tag uint32) (*List, bool) {
	if elem, found := e.elements[tag]; found && elem.GetType() == TypeList {
		return elem.(*List), true
	}

	return nil, false
}

//=============================================================================
// List
//=============================================================================

// AddInt8 adds an 8 bit unsigned integer with the specified tag to the List.
func (e *List) AddInt8(number uint8) *List {
	if e.elemType == TypeRu8 {
		e.elements = append(e.elements, &ru8{rElem: rElem{typ: TypeRu8}, value: number})
		return e
	}
	return nil
}

// AddInt16 adds an 16 bit unsigned integer with the specified tag to the List.
func (e *List) AddInt16(number uint16) *List {
	if e.elemType == TypeRu16 {
		e.elements = append(e.elements, &ru16{rElem: rElem{typ: TypeRu16}, value: number})
		return e
	}
	return nil
}

// AddInt32 adds an 32 bit unsigned integer with the specified tag to the List.
func (e *List) AddInt32(number uint32) *List {
	if e.elemType == TypeRu32 {
		e.elements = append(e.elements, &ru32{rElem: rElem{typ: TypeRu32}, value: number})
		return e
	}
	return nil
}

// AddInt64 adds an 64 bit unsigned integer with the specified tag to the List.
func (e *List) AddInt64(number uint64) *List {
	if e.elemType == TypeRu64 {
		e.elements = append(e.elements, &ru64{rElem: rElem{typ: TypeRu64}, value: number})
		return e
	}
	return nil
}

// AddStringA adds an ascii string with the specified tag to the List.
func (e *List) AddStringA(str string) *List {
	if e.elemType == TypeStringA {
		e.elements = append(e.elements, &rStringA{rElem: rElem{typ: TypeStringA}, value: str})
		return e
	}
	return nil
}

// AddStringW adds a wide character string with the specified tag to the List.
func (e *List) AddStringW(str string) *List {
	if e.elemType == TypeStringW {
		e.elements = append(e.elements, &rStringW{rElem: rElem{typ: TypeStringW}, value: str})
		return e
	}
	return nil
}

// AddBuffer adds a buffer with the specified tag to the List.
func (e *List) AddBuffer(buf []byte) *List {
	if e.elemType == TypeBuffer {
		e.elements = append(e.elements, &rBuffer{rElem: rElem{typ: TypeBuffer}, value: buf})
		return e
	}
	return nil
}

// AddTimestamp adds a timestamp with the specified tag to the List.
func (e *List) AddTimestamp(ts uint64) *List {
	if e.elemType == TypeTimestamp {
		e.elements = append(e.elements, &rTimestamp{rElem: rElem{typ: TypeTimestamp}, value: ts})
		return e
	}
	return nil
}

// AddIPv4 adds an IP v4 with the specified tag to the List.
func (e *List) AddIPv4(ip4 net.IP) *List {
	if e.elemType == TypeIPv4 {
		e.elements = append(e.elements, &rIPv4{rElem: rElem{typ: TypeIPv4}, value: ip4.To4()})
		return e
	}
	return nil
}

// AddIPv6 adds an IP v6 with the specified tag to the List.
func (e *List) AddIPv6(ip6 net.IP) *List {
	if e.elemType == TypeIPv6 {
		e.elements = append(e.elements, &rIPv6{rElem: rElem{typ: TypeIPv6}, value: ip6.To16()})
		return e
	}
	return nil
}

// AddPointer32 adds a 32 bit pointer with the specified tag to the List.
func (e *List) AddPointer32(ptr uint32) *List {
	if e.elemType == TypePointer32 {
		e.elements = append(e.elements, &rPointer32{rElem: rElem{typ: TypePointer32}, value: ptr})
		return e
	}
	return nil
}

// AddPointer64 adds a 64 bit pointer with the specified tag to the List.
func (e *List) AddPointer64(ptr uint64) *List {
	if e.elemType == TypePointer64 {
		e.elements = append(e.elements, &rPointer64{rElem: rElem{typ: TypePointer64}, value: ptr})
		return e
	}
	return nil
}

// AddTimedelta adds a time delta with the specified tag to the List.
func (e *List) AddTimedelta(td uint64) *List {
	if e.elemType == TypeTimedelta {
		e.elements = append(e.elements, &rTimedelta{rElem: rElem{typ: TypeTimedelta}, value: td})
		return e
	}
	return nil
}

// AddSequence adds a Sequence with the specified tag to the List.
func (e *List) AddSequence(seq *Sequence) *List {
	if e.elemType == TypeSequence {
		seq.typ = TypeSequence
		e.elements = append(e.elements, seq)
		return e
	}
	return nil
}

// AddList adds a List with the specified tag to the List.
func (e *List) AddList(list *List) *List {
	if e.elemType == TypeList {
		list.typ = TypeList
		e.elements = append(e.elements, list)
		return e
	}
	return nil
}

// GetInt8 returns an 8 bit unsigned integer with the specific tag, if present.
func (e *List) GetInt8(tag uint32) []uint8 {
	res := make([]uint8, 0)

	if TypeRu8 == e.elemType && tag == e.elemTag {
		for _, e := range e.elements {
			res = append(res, e.(*ru8).value)
		}
	}

	return res
}

// GetInt16 returns an 16 bit unsigned integer with the specific tag, if present.
func (e *List) GetInt16(tag uint32) []uint16 {
	res := make([]uint16, 0)

	if TypeRu16 == e.elemType && tag == e.elemTag {
		for _, e := range e.elements {
			res = append(res, e.(*ru16).value)
		}
	}

	return res
}

// GetInt32 returns an 32 bit unsigned integer with the specific tag, if present.
func (e *List) GetInt32(tag uint32) []uint32 {
	res := make([]uint32, 0)

	if TypeRu32 == e.elemType && tag == e.elemTag {
		for _, e := range e.elements {
			res = append(res, e.(*ru32).value)
		}
	}

	return res
}

// GetInt64 returns an 64 bit unsigned integer with the specific tag, if present.
func (e *List) GetInt64(tag uint32) []uint64 {
	res := make([]uint64, 0)

	if TypeRu64 == e.elemType && tag == e.elemTag {
		for _, e := range e.elements {
			res = append(res, e.(*ru64).value)
		}
	}

	return res
}

// GetStringA returns an ascii string with the specific tag, if present.
func (e *List) GetStringA(tag uint32) []string {
	res := make([]string, 0)

	if TypeStringA == e.elemType && tag == e.elemTag {
		for _, e := range e.elements {
			res = append(res, e.(*rStringA).value)
		}
	}

	return res
}

// GetStringW returns a wide character string with the specific tag, if present.
func (e *List) GetStringW(tag uint32) []string {
	res := make([]string, 0)

	if TypeStringW == e.elemType && tag == e.elemTag {
		for _, e := range e.elements {
			res = append(res, e.(*rStringW).value)
		}
	}

	return res
}

// GetBuffer returns a buffer with the specific tag, if present.
func (e *List) GetBuffer(tag uint32) [][]byte {
	res := make([][]byte, 0)

	if TypeBuffer == e.elemType && tag == e.elemTag {
		for _, e := range e.elements {
			res = append(res, e.(*rBuffer).value)
		}
	}

	return res
}

// GetTimestamp returns a timestamp with the specific tag, if present.
func (e *List) GetTimestamp(tag uint32) []uint64 {
	res := make([]uint64, 0)

	if TypeTimestamp == e.elemType && tag == e.elemTag {
		for _, e := range e.elements {
			res = append(res, e.(*rTimestamp).value)
		}
	}

	return res
}

// GetIPv4 returns an IP v4 with the specific tag, if present.
func (e *List) GetIPv4(tag uint32) []net.IP {
	res := make([]net.IP, 0)

	if TypeIPv4 == e.elemType && tag == e.elemTag {
		for _, e := range e.elements {
			res = append(res, e.(*rIPv4).value.To4())
		}
	}

	return res
}

// GetIPv6 returns an IP v6 with the specific tag, if present.
func (e *List) GetIPv6(tag uint32) []net.IP {
	res := make([]net.IP, 0)

	if TypeIPv6 == e.elemType && tag == e.elemTag {
		for _, e := range e.elements {
			res = append(res, e.(*rIPv6).value.To16())
		}
	}

	return res
}

// GetPointer32 returns a 32 bit pointer with the specific tag, if present.
func (e *List) GetPointer32(tag uint32) []uint32 {
	res := make([]uint32, 0)

	if TypePointer32 == e.elemType && tag == e.elemTag {
		for _, e := range e.elements {
			res = append(res, e.(*rPointer32).value)
		}
	}

	return res
}

// GetPointer64 returns a 64 bit pointer with the specific tag, if present.
func (e *List) GetPointer64(tag uint32) []uint64 {
	res := make([]uint64, 0)

	if TypePointer64 == e.elemType && tag == e.elemTag {
		for _, e := range e.elements {
			res = append(res, e.(*rPointer64).value)
		}
	}

	return res
}

// GetTimedelta returns a time delta with the specific tag, if present.
func (e *List) GetTimedelta(tag uint32) []uint64 {
	res := make([]uint64, 0)

	if TypeTimedelta == e.elemType && tag == e.elemTag {
		for _, e := range e.elements {
			res = append(res, e.(*rTimedelta).value)
		}
	}

	return res
}

// GetSequence returns a Sequence with the specific tag, if present.
func (e *List) GetSequence(tag uint32) []*Sequence {
	res := make([]*Sequence, 0)

	if TypeSequence == e.elemType && tag == e.elemTag {
		for _, e := range e.elements {
			res = append(res, e.(*Sequence))
		}
	}

	return res
}

// GetList returns a List with the specific tag, if present.
func (e *List) GetList(tag uint32) []*List {
	res := make([]*List, 0)

	if TypeList == e.elemType && tag == e.elemTag {
		for _, e := range e.elements {
			res = append(res, e.(*List))
		}
	}

	return res
}
