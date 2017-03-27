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

type rIpv4 struct {
	rElem
	value uint32
}

type rIpv6 struct {
	rElem
	value [16]byte
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

func (this *rElem) GetType() uint8 {
	return this.typ
}

func (this *ru8) GetValue() interface{} {
	return this.value
}

func (this *ru16) GetValue() interface{} {
	return this.value
}

func (this *ru32) GetValue() interface{} {
	return this.value
}

func (this *ru64) GetValue() interface{} {
	return this.value
}

func (this *rStringA) GetValue() interface{} {
	return this.value
}

func (this *rStringW) GetValue() interface{} {
	return this.value
}

func (this *rBuffer) GetValue() interface{} {
	return this.value
}

func (this *rTimestamp) GetValue() interface{} {
	return this.value
}

func (this *rIpv4) GetValue() interface{} {
	return this.value
}

func (this *rIpv6) GetValue() interface{} {
	return this.value
}

func (this *rPointer32) GetValue() interface{} {
	return this.value
}

func (this *rPointer64) GetValue() interface{} {
	return this.value
}

func (this *rTimedelta) GetValue() interface{} {
	return this.value
}

func (this *Sequence) GetValue() interface{} {
	return this.elements
}

func (this *List) GetValue() interface{} {
	return this.elements
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

func (this *ru8) serialize(toBuf *bytes.Buffer) error {
	return toBuf.WriteByte(this.value)
}

func (this *ru16) serialize(toBuf *bytes.Buffer) error {
	return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *ru32) serialize(toBuf *bytes.Buffer) error {
	return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *ru64) serialize(toBuf *bytes.Buffer) error {
	return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *rStringA) serialize(toBuf *bytes.Buffer) error {
	err := binary.Write(toBuf, binary.BigEndian, uint32(len(this.value)+1))
	if err != nil {
		return err
	}
	_, err = toBuf.Write([]byte(this.value))
	if err != nil {
		return err
	}
	err = toBuf.WriteByte(0)
	if err != nil {
		return err
	}

	return nil
}

func (this *rStringW) serialize(toBuf *bytes.Buffer) error {
	err := binary.Write(toBuf, binary.BigEndian, uint32(len(this.value)+1))
	if err != nil {
		return err
	}
	_, err = toBuf.Write([]byte(this.value))
	if err != nil {
		return err
	}
	err = toBuf.WriteByte(0)
	if err != nil {
		return err
	}

	return nil
}

func (this *rBuffer) serialize(toBuf *bytes.Buffer) error {
	err := binary.Write(toBuf, binary.BigEndian, uint32(len(this.value)))
	if err != nil {
		return err
	}
	_, err = toBuf.Write(this.value)
	if err != nil {
		return err
	}

	return nil
}

func (this *rTimestamp) serialize(toBuf *bytes.Buffer) error {
	return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *rIpv4) serialize(toBuf *bytes.Buffer) error {
	return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *rIpv6) serialize(toBuf *bytes.Buffer) error {
	return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *rPointer32) serialize(toBuf *bytes.Buffer) error {
	return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *rPointer64) serialize(toBuf *bytes.Buffer) error {
	return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *rTimedelta) serialize(toBuf *bytes.Buffer) error {
	return binary.Write(toBuf, binary.BigEndian, this.value)
}

// Serialize convertts the Sequence structure in a slice of bytes that can be used
// to restore the original Sequence regardless of the platform.
func (this *Sequence) Serialize(toBuf *bytes.Buffer) error {
    return this.serialize(toBuf)
}

func (this *Sequence) serialize(toBuf *bytes.Buffer) error {
	err := binary.Write(toBuf, binary.BigEndian, uint32(len(this.elements)))
	if err != nil {
		return err
	}
	for tag, elem := range this.elements {
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
func (this *List) Serialize(toBuf *bytes.Buffer) error {
    return this.serialize(toBuf)
}

func (this *List) serialize(toBuf *bytes.Buffer) error {
	err := binary.Write(toBuf, binary.BigEndian, this.elemTag)
	if err != nil {
		return err
	}
	err = binary.Write(toBuf, binary.BigEndian, this.elemType)
	if err != nil {
		return err
	}
	err = binary.Write(toBuf, binary.BigEndian, uint32(len(this.elements)))
	if err != nil {
		return err
	}
	for _, elem := range this.elements {
		if this.elemType != elem.GetType() {
			return errors.New("Sanity failure: list contains unexpected type.")
		}
		err = binary.Write(toBuf, binary.BigEndian, this.elemTag)
		if err != nil {
			return err
		}
		err = binary.Write(toBuf, binary.BigEndian, this.elemType)
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
func (this *Sequence) Deserialize(fromBuf *bytes.Buffer) error {
	var nElements uint32
	var tag uint32
	var typ uint8
	var err error

	this.typ = TypeSequence

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
			return errors.New("Failed to deserialize an element.")
		}

		this.elements[tag] = tmpElem
	}

	return err
}

// Deserialize a slice of bytes into the List it represents.
func (this *List) Deserialize(fromBuf *bytes.Buffer) error {
	var nElements uint32
	var tag uint32
	var typ uint8
	var err error

	this.typ = TypeList

	err = binary.Read(fromBuf, binary.BigEndian, &this.elemTag)
	if err != nil {
		return err
	}

	err = binary.Read(fromBuf, binary.BigEndian, &this.elemType)
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
		if tag != this.elemTag {
			return errors.New("Sanity failure: element tag in list does not match.")
		}
		err = binary.Read(fromBuf, binary.BigEndian, &typ)
		if err != nil {
			return err
		}
		if typ != this.elemType {
			return errors.New("Sanity failure: element type in list does not match.")
		}
		tmpElem, err = rpcmDeserializeElem(fromBuf, typ)
		if tmpElem == nil || err != nil {
			return errors.New("Failed to deserialize an element.")
		}

		this.elements = append(this.elements, tmpElem)
	}

	return err
}

func rpcmDeserializeElem(fromBuf *bytes.Buffer, typ uint8) (rpcmElement, error) {
	var elem rpcmElement = nil
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
			err = errors.New("Not enough data in buffer")
		} else {
			tmpBuf = make([]byte, elemLen)
			sizeRead, err = fromBuf.Read(tmpBuf)
			if uint32(sizeRead) != elemLen {
				err = errors.New("Error reading enough data from buffer")
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
		elem = &rIpv4{rElem: rElem{typ: typ}}
		err = binary.Read(fromBuf, binary.BigEndian, &elem.(*rIpv4).value)
	case TypeIPv6:
		elem = &rIpv6{rElem: rElem{typ: typ}}
		sizeRead, err = fromBuf.Read(elem.(*rIpv6).value[:])
		if uint32(sizeRead) != 16 {
			err = errors.New("Error reading enough data from buffer")
		}
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
func (this *Sequence) ToMachine() MachineSequence {
	j := make(map[uint32]interface{})

	for tag, val := range this.elements {
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
func (this *List) ToMachine() MachineList {
	j := make([]interface{}, 0)

	for _, val := range this.elements {
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

// ToMachine takes a Sequence and turns it into the JSON compatible format.
func (this *Sequence) ToJson() map[string]interface{} {
	var tagLabel string
	var ok bool

	j := make(map[string]interface{})

	for tag, val := range this.elements {
		if tagLabel, ok = HumanReadableTags[tag]; !ok {
			tagLabel = strconv.FormatUint(uint64(tag), 16)
		}

		if val.GetType() == TypeSequence {
			j[tagLabel] = val.(*Sequence).ToJson()
		} else if val.GetType() == TypeList {
			j[tagLabel] = val.(*List).ToJson()
		} else {
			j[tagLabel] = val.GetValue()
		}
	}

	return j
}

// ToMachine takes a List and turns it into the JSON compatible format.
func (this *List) ToJson() []interface{} {
	j := make([]interface{}, 0)

	for _, val := range this.elements {
		if val.GetType() == TypeSequence {
			j = append(j, val.(*Sequence).ToJson())
		} else if val.GetType() == TypeList {
			j = append(j, val.(*List).ToJson())
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
func (this *Sequence) AddInt8(tag uint32, number uint8) *Sequence {
	this.elements[tag] = &ru8{rElem: rElem{typ: TypeRu8}, value: number}
	return this
}

// AddInt16 adds an 16 bit unsigned integer with the specified tag to the Sequence.
func (this *Sequence) AddInt16(tag uint32, number uint16) *Sequence {
	this.elements[tag] = &ru16{rElem: rElem{typ: TypeRu16}, value: number}
	return this
}

// AddInt32 adds an 32 bit unsigned integer with the specified tag to the Sequence.
func (this *Sequence) AddInt32(tag uint32, number uint32) *Sequence {
	this.elements[tag] = &ru32{rElem: rElem{typ: TypeRu32}, value: number}
	return this
}

// AddInt64 adds an 64 bit unsigned integer with the specified tag to the Sequence.
func (this *Sequence) AddInt64(tag uint32, number uint64) *Sequence {
	this.elements[tag] = &ru64{rElem: rElem{typ: TypeRu64}, value: number}
	return this
}

// AddStringA adds a ascii string with the specified tag to the Sequence.
func (this *Sequence) AddStringA(tag uint32, str string) *Sequence {
	this.elements[tag] = &rStringA{rElem: rElem{typ: TypeStringA}, value: str}
	return this
}

// AddStringW adds a wide character string with the specified tag to the Sequence.
func (this *Sequence) AddStringW(tag uint32, str string) *Sequence {
	this.elements[tag] = &rStringW{rElem: rElem{typ: TypeStringW}, value: str}
	return this
}

// AddBuffer adds a buffer with the specified tag to the Sequence.
func (this *Sequence) AddBuffer(tag uint32, buf []byte) *Sequence {
	this.elements[tag] = &rBuffer{rElem: rElem{typ: TypeBuffer}, value: buf}
	return this
}

// AddTimestamp adds a 64 bit timestamp with the specified tag to the Sequence.
func (this *Sequence) AddTimestamp(tag uint32, ts uint64) *Sequence {
	this.elements[tag] = &rTimestamp{rElem: rElem{typ: TypeTimestamp}, value: ts}
	return this
}

// AddIpv4 adds an IP v4 with the specified tag to the Sequence.
func (this *Sequence) AddIpv4(tag uint32, ip4 uint32) *Sequence {
	this.elements[tag] = &rIpv4{rElem: rElem{typ: TypeIPv4}, value: ip4}
	return this
}

// AddIpv6 adds an IP v6 with the specified tag to the Sequence.
func (this *Sequence) AddIpv6(tag uint32, ip6 [16]byte) *Sequence {
	this.elements[tag] = &rIpv6{rElem: rElem{typ: TypeIPv6}, value: ip6}
	return this
}

// AddPointer32 adds a 32 bit pointer with the specified tag to the Sequence.
func (this *Sequence) AddPointer32(tag uint32, ptr uint32) *Sequence {
	this.elements[tag] = &rPointer32{rElem: rElem{typ: TypePointer32}, value: ptr}
	return this
}

// AddPointer64 adds a 64 bit pointer with the specified tag to the Sequence.
func (this *Sequence) AddPointer64(tag uint32, ptr uint64) *Sequence {
	this.elements[tag] = &rPointer64{rElem: rElem{typ: TypePointer64}, value: ptr}
	return this
}

// AddTimedelta adds a time delta with the specified tag to the Sequence.
func (this *Sequence) AddTimedelta(tag uint32, td uint64) *Sequence {
	this.elements[tag] = &rTimedelta{rElem: rElem{typ: TypeTimedelta}, value: td}
	return this
}

// AddSequence adds a Sequence with the specified tag to the Sequence.
func (this *Sequence) AddSequence(tag uint32, seq *Sequence) *Sequence {
	seq.typ = TypeSequence
	this.elements[tag] = seq
	return this
}

// AddList adds a List with the specified tag to the Sequence.
func (this *Sequence) AddList(tag uint32, list *List) *Sequence {
	list.typ = TypeList
	this.elements[tag] = list
	return this
}

// GetInt8 returns an 8 bit unsigned integer with the specific tag, if present.
func (this *Sequence) GetInt8(tag uint32) (uint8, bool) {
	var res uint8
	var ok bool

	if elem, found := this.elements[tag]; found && elem.GetType() == TypeRu8 {
		ok = true
		res = elem.(*ru8).value
	}

	return res, ok
}

// GetInt16 returns an 16 bit unsigned integer with the specific tag, if present.
func (this *Sequence) GetInt16(tag uint32) (uint16, bool) {
	var res uint16
	var ok bool

	if elem, found := this.elements[tag]; found && elem.GetType() == TypeRu16 {
		ok = true
		res = elem.(*ru16).value
	}

	return res, ok
}

// GetInt32 returns an 32 bit unsigned integer with the specific tag, if present.
func (this *Sequence) GetInt32(tag uint32) (uint32, bool) {
	var res uint32
	var ok bool

	if elem, found := this.elements[tag]; found && elem.GetType() == TypeRu32 {
		ok = true
		res = elem.(*ru32).value
	}

	return res, ok
}

// GetInt64 returns an 64 bit unsigned integer with the specific tag, if present.
func (this *Sequence) GetInt64(tag uint32) (uint64, bool) {
	var res uint64
	var ok bool

	if elem, found := this.elements[tag]; found && elem.GetType() == TypeRu64 {
		ok = true
		res = elem.(*ru64).value
	}

	return res, ok
}

// GetStringA returns an ascii string with the specific tag, if present.
func (this *Sequence) GetStringA(tag uint32) (string, bool) {
	var res string
	var ok bool

	if elem, found := this.elements[tag]; found && elem.GetType() == TypeStringA {
		ok = true
		res = elem.(*rStringA).value
	}

	return res, ok
}

// GetStringW returns a wide character string with the specific tag, if present.
func (this *Sequence) GetStringW(tag uint32) (string, bool) {
	var res string
	var ok bool

	if elem, found := this.elements[tag]; found && elem.GetType() == TypeStringW {
		ok = true
		res = elem.(*rStringW).value
	}

	return res, ok
}

// GetBuffer returns a buffer with the specific tag, if present.
func (this *Sequence) GetBuffer(tag uint32) ([]byte, bool) {
	var res []byte
	var ok bool

	if elem, found := this.elements[tag]; found && elem.GetType() == TypeBuffer {
		ok = true
		res = elem.(*rBuffer).value
	}

	return res, ok
}

// GetTimestamp returns a timestamp with the specific tag, if present.
func (this *Sequence) GetTimestamp(tag uint32) (uint64, bool) {
	var res uint64
	var ok bool

	if elem, found := this.elements[tag]; found && elem.GetType() == TypeTimestamp {
		ok = true
		res = elem.(*rTimestamp).value
	}

	return res, ok
}

// GetIpv4 returns an IP v4 with the specific tag, if present.
func (this *Sequence) GetIpv4(tag uint32) (uint32, bool) {
	var res uint32
	var ok bool

	if elem, found := this.elements[tag]; found && elem.GetType() == TypeIPv4 {
		ok = true
		res = elem.(*rIpv4).value
	}

	return res, ok
}

// GetIpv6 returns an IP v6 with the specific tag, if present.
func (this *Sequence) GetIpv6(tag uint32) ([16]byte, bool) {
	var res [16]byte
	var ok bool

	if elem, found := this.elements[tag]; found && elem.GetType() == TypeIPv6 {
		ok = true
		res = elem.(*rIpv6).value
	}

	return res, ok
}

// GetPointer32 returns a 32 bit pointer with the specific tag, if present.
func (this *Sequence) GetPointer32(tag uint32) (uint32, bool) {
	var res uint32
	var ok bool

	if elem, found := this.elements[tag]; found && elem.GetType() == TypePointer32 {
		ok = true
		res = elem.(*rPointer32).value
	}

	return res, ok
}

// GetPointer64 returns a 64 bit pointer with the specific tag, if present.
func (this *Sequence) GetPointer64(tag uint32) (uint64, bool) {
	var res uint64
	var ok bool

	if elem, found := this.elements[tag]; found && elem.GetType() == TypePointer64 {
		ok = true
		res = elem.(*rPointer64).value
	}

	return res, ok
}

// GetTimedelta returns a time delta with the specific tag, if present.
func (this *Sequence) GetTimedelta(tag uint32) (uint64, bool) {
	var res uint64
	var ok bool

	if elem, found := this.elements[tag]; found && elem.GetType() == TypeTimedelta {
		ok = true
		res = elem.(*rTimedelta).value
	}

	return res, ok
}

// GetSequence returns a Sequence with the specific tag, if present.
func (this *Sequence) GetSequence(tag uint32) (*Sequence, bool) {
	var res *Sequence
	var ok bool

	if elem, found := this.elements[tag]; found && elem.GetType() == TypeSequence {
		ok = true
		res = elem.(*Sequence)
	}

	return res, ok
}

// GetList returns a List with the specific tag, if present.
func (this *Sequence) GetList(tag uint32) (*List, bool) {
	var res *List
	var ok bool

	if elem, found := this.elements[tag]; found && elem.GetType() == TypeList {
		ok = true
		res = elem.(*List)
	}

	return res, ok
}

//=============================================================================
// List
//=============================================================================

// AddInt8 adds an 8 bit unsigned integer with the specified tag to the List.
func (this *List) AddInt8(number uint8) *List {
	if this.elemType == TypeRu8 {
		this.elements = append(this.elements, &ru8{rElem: rElem{typ: TypeRu8}, value: number})
		return this
	}
	return nil
}

// AddInt16 adds an 16 bit unsigned integer with the specified tag to the List.
func (this *List) AddInt16(number uint16) *List {
	if this.elemType == TypeRu16 {
		this.elements = append(this.elements, &ru16{rElem: rElem{typ: TypeRu16}, value: number})
		return this
	}
	return nil
}

// AddInt32 adds an 32 bit unsigned integer with the specified tag to the List.
func (this *List) AddInt32(number uint32) *List {
	if this.elemType == TypeRu32 {
		this.elements = append(this.elements, &ru32{rElem: rElem{typ: TypeRu32}, value: number})
		return this
	}
	return nil
}

// AddInt64 adds an 64 bit unsigned integer with the specified tag to the List.
func (this *List) AddInt64(number uint64) *List {
	if this.elemType == TypeRu64 {
		this.elements = append(this.elements, &ru64{rElem: rElem{typ: TypeRu64}, value: number})
		return this
	}
	return nil
}

// AddStringA adds an ascii string with the specified tag to the List.
func (this *List) AddStringA(str string) *List {
	if this.elemType == TypeStringA {
		this.elements = append(this.elements, &rStringA{rElem: rElem{typ: TypeStringA}, value: str})
		return this
	}
	return nil
}

// AddStringW adds a wide character string with the specified tag to the List.
func (this *List) AddStringW(str string) *List {
	if this.elemType == TypeStringW {
		this.elements = append(this.elements, &rStringW{rElem: rElem{typ: TypeStringW}, value: str})
		return this
	}
	return nil
}

// AddBuffer adds a buffer with the specified tag to the List.
func (this *List) AddBuffer(buf []byte) *List {
	if this.elemType == TypeBuffer {
		this.elements = append(this.elements, &rBuffer{rElem: rElem{typ: TypeBuffer}, value: buf})
		return this
	}
	return nil
}

// AddTimestamp adds a timestamp with the specified tag to the List.
func (this *List) AddTimestamp(ts uint64) *List {
	if this.elemType == TypeTimestamp {
		this.elements = append(this.elements, &rTimestamp{rElem: rElem{typ: TypeTimestamp}, value: ts})
		return this
	}
	return nil
}

// AddIpv4 adds an IP v4 with the specified tag to the List.
func (this *List) AddIpv4(ip4 uint32) *List {
	if this.elemType == TypeIPv4 {
		this.elements = append(this.elements, &rIpv4{rElem: rElem{typ: TypeIPv4}, value: ip4})
		return this
	}
	return nil
}

// AddIpv6 adds an IP v6 with the specified tag to the List.
func (this *List) AddIpv6(ip6 [16]byte) *List {
	if this.elemType == TypeIPv6 {
		this.elements = append(this.elements, &rIpv6{rElem: rElem{typ: TypeIPv6}, value: ip6})
		return this
	}
	return nil
}

// AddPointer32 adds a 32 bit pointer with the specified tag to the List.
func (this *List) AddPointer32(ptr uint32) *List {
	if this.elemType == TypePointer32 {
		this.elements = append(this.elements, &rPointer32{rElem: rElem{typ: TypePointer32}, value: ptr})
		return this
	}
	return nil
}

// AddPointer64 adds a 64 bit pointer with the specified tag to the List.
func (this *List) AddPointer64(ptr uint64) *List {
	if this.elemType == TypePointer64 {
		this.elements = append(this.elements, &rPointer64{rElem: rElem{typ: TypePointer64}, value: ptr})
		return this
	}
	return nil
}

// AddTimedelta adds a time delta with the specified tag to the List.
func (this *List) AddTimedelta(td uint64) *List {
	if this.elemType == TypeTimedelta {
		this.elements = append(this.elements, &rTimedelta{rElem: rElem{typ: TypeTimedelta}, value: td})
		return this
	}
	return nil
}

// AddSequence adds a Sequence with the specified tag to the List.
func (this *List) AddSequence(seq *Sequence) *List {
	if this.elemType == TypeSequence {
		seq.typ = TypeSequence
		this.elements = append(this.elements, seq)
		return this
	}
	return nil
}

// AddList adds a List with the specified tag to the List.
func (this *List) AddList(list *List) *List {
	if this.elemType == TypeList {
		list.typ = TypeList
		this.elements = append(this.elements, list)
		return this
	}
	return nil
}

// GetInt8 returns an 8 bit unsigned integer with the specific tag, if present.
func (this *List) GetInt8(tag uint32) []uint8 {
	res := make([]uint8, 0)

	if TypeRu8 == this.elemType && tag == this.elemTag {
		for _, e := range this.elements {
			res = append(res, e.(*ru8).value)
		}
	}

	return res
}

// GetInt16 returns an 16 bit unsigned integer with the specific tag, if present.
func (this *List) GetInt16(tag uint32) []uint16 {
	res := make([]uint16, 0)

	if TypeRu16 == this.elemType && tag == this.elemTag {
		for _, e := range this.elements {
			res = append(res, e.(*ru16).value)
		}
	}

	return res
}

// GetInt32 returns an 32 bit unsigned integer with the specific tag, if present.
func (this *List) GetInt32(tag uint32) []uint32 {
	res := make([]uint32, 0)

	if TypeRu32 == this.elemType && tag == this.elemTag {
		for _, e := range this.elements {
			res = append(res, e.(*ru32).value)
		}
	}

	return res
}

// GetInt64 returns an 64 bit unsigned integer with the specific tag, if present.
func (this *List) GetInt64(tag uint32) []uint64 {
	res := make([]uint64, 0)

	if TypeRu64 == this.elemType && tag == this.elemTag {
		for _, e := range this.elements {
			res = append(res, e.(*ru64).value)
		}
	}

	return res
}

// GetStringA returns an ascii string with the specific tag, if present.
func (this *List) GetStringA(tag uint32) []string {
	res := make([]string, 0)

	if TypeStringA == this.elemType && tag == this.elemTag {
		for _, e := range this.elements {
			res = append(res, e.(*rStringA).value)
		}
	}

	return res
}

// GetStringW returns a wide character string with the specific tag, if present.
func (this *List) GetStringW(tag uint32) []string {
	res := make([]string, 0)

	if TypeStringW == this.elemType && tag == this.elemTag {
		for _, e := range this.elements {
			res = append(res, e.(*rStringW).value)
		}
	}

	return res
}

// GetBuffer returns a buffer with the specific tag, if present.
func (this *List) GetBuffer(tag uint32) [][]byte {
	res := make([][]byte, 0)

	if TypeBuffer == this.elemType && tag == this.elemTag {
		for _, e := range this.elements {
			res = append(res, e.(*rBuffer).value)
		}
	}

	return res
}

// GetTimestamp returns a timestamp with the specific tag, if present.
func (this *List) GetTimestamp(tag uint32) []uint64 {
	res := make([]uint64, 0)

	if TypeTimestamp == this.elemType && tag == this.elemTag {
		for _, e := range this.elements {
			res = append(res, e.(*rTimestamp).value)
		}
	}

	return res
}

// GetIpv4 returns an IP v4 with the specific tag, if present.
func (this *List) GetIpv4(tag uint32) []uint32 {
	res := make([]uint32, 0)

	if TypeIPv4 == this.elemType && tag == this.elemTag {
		for _, e := range this.elements {
			res = append(res, e.(*rIpv4).value)
		}
	}

	return res
}

// GetIpv6 returns an IP v6 with the specific tag, if present.
func (this *List) GetIpv6(tag uint32) [][16]byte {
	res := make([][16]byte, 0)

	if TypeIPv6 == this.elemType && tag == this.elemTag {
		for _, e := range this.elements {
			res = append(res, e.(*rIpv6).value)
		}
	}

	return res
}

// GetPointer32 returns a 32 bit pointer with the specific tag, if present.
func (this *List) GetPointer32(tag uint32) []uint32 {
	res := make([]uint32, 0)

	if TypePointer32 == this.elemType && tag == this.elemTag {
		for _, e := range this.elements {
			res = append(res, e.(*rPointer32).value)
		}
	}

	return res
}

// GetPointer64 returns a 64 bit pointer with the specific tag, if present.
func (this *List) GetPointer64(tag uint32) []uint64 {
	res := make([]uint64, 0)

	if TypePointer64 == this.elemType && tag == this.elemTag {
		for _, e := range this.elements {
			res = append(res, e.(*rPointer64).value)
		}
	}

	return res
}

// GetTimedelta returns a time delta with the specific tag, if present.
func (this *List) GetTimedelta(tag uint32) []uint64 {
	res := make([]uint64, 0)

	if TypeTimedelta == this.elemType && tag == this.elemTag {
		for _, e := range this.elements {
			res = append(res, e.(*rTimedelta).value)
		}
	}

	return res
}

// GetSequence returns a Sequence with the specific tag, if present.
func (this *List) GetSequence(tag uint32) []*Sequence {
	res := make([]*Sequence, 0)

	if TypeSequence == this.elemType && tag == this.elemTag {
		for _, e := range this.elements {
			res = append(res, e.(*Sequence))
		}
	}

	return res
}

// GetList returns a List with the specific tag, if present.
func (this *List) GetList(tag uint32) []*List {
	res := make([]*List, 0)

	if TypeList == this.elemType && tag == this.elemTag {
		for _, e := range this.elements {
			res = append(res, e.(*List))
		}
	}

	return res
}
