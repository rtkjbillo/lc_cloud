package rpcm

import (
    "bytes"
    "errors"
    "strconv"
    "encoding/binary"
)

const (
    RPCM_INVALID_TYPE = 0
    RPCM_RU8 = 1
    RPCM_RU16 = 2
    RPCM_RU32 = 3
    RPCM_RU64 = 4
    RPCM_STRINGA = 5
    RPCM_STRINGW = 6
    RPCM_BUFFER = 7
    RPCM_TIMESTAMP = 8
    RPCM_IPV4 = 9
    RPCM_IPV6 = 10
    RPCM_POINTER_32 = 11
    RPCM_POINTER_64 = 12
    RPCM_TIMEDELTA = 13
    RPCM_COMPLEX_TYPES = 0x80
    RPCM_SEQUENCE = 0x81
    RPCM_LIST = 0x82
)

type rpcmElement interface {
    GetType() byte
    GetValue() interface{}
    Serialize(toBuf *bytes.Buffer) error
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
    elemTag uint32
    elemType uint8
    iterator int
    elements []rpcmElement
}

type MachineSequence map[uint32]interface{}
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
func NewSequence() *Sequence {
    return &Sequence{rElem: rElem{RPCM_SEQUENCE}, elements: make(map[uint32]rpcmElement)}
}

func NewList(elemTag uint32, elemType uint8) *List {
    return &List{rElem: rElem{RPCM_LIST}, elemTag : elemTag, elemType : elemType}
}

//=============================================================================
// Serialize
//=============================================================================
func (this *ru8) Serialize(toBuf *bytes.Buffer) error {
    return toBuf.WriteByte(this.value)
}

func (this *ru16) Serialize(toBuf *bytes.Buffer) error {
    return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *ru32) Serialize(toBuf *bytes.Buffer) error {
    return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *ru64) Serialize(toBuf *bytes.Buffer) error {
    return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *rStringA) Serialize(toBuf *bytes.Buffer) error {
    err := binary.Write(toBuf, binary.BigEndian, uint32(len(this.value) + 1))
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

func (this *rStringW) Serialize(toBuf *bytes.Buffer) error {
    err := binary.Write(toBuf, binary.BigEndian, uint32(len(this.value) + 1))
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

func (this *rBuffer) Serialize(toBuf *bytes.Buffer) error {
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

func (this *rTimestamp) Serialize(toBuf *bytes.Buffer) error {
    return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *rIpv4) Serialize(toBuf *bytes.Buffer) error {
    return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *rIpv6) Serialize(toBuf *bytes.Buffer) error {
    return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *rPointer32) Serialize(toBuf *bytes.Buffer) error {
    return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *rPointer64) Serialize(toBuf *bytes.Buffer) error {
    return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *rTimedelta) Serialize(toBuf *bytes.Buffer) error {
    return binary.Write(toBuf, binary.BigEndian, this.value)
}

func (this *Sequence) Serialize(toBuf *bytes.Buffer) error {
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
        err = elem.Serialize(toBuf)
        if err != nil {
            return err
        }
    }
    return nil
}

func (this *List) Serialize(toBuf *bytes.Buffer) error {
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
        err = elem.Serialize(toBuf)
        if err != nil {
            return err
        }
    }
    return nil
}

//=============================================================================
// Deserialize
//=============================================================================
func (this *Sequence)Deserialize(fromBuf *bytes.Buffer) error {
    var nElements uint32
    var tag uint32
    var typ uint8
    var err error

    this.typ = RPCM_SEQUENCE

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

func (this *List)Deserialize(fromBuf *bytes.Buffer) error {
    var nElements uint32
    var tag uint32
    var typ uint8
    var err error

    this.typ = RPCM_LIST

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
        case RPCM_RU8:
            elem = &ru8{rElem: rElem{typ: RPCM_RU8}}
            err = binary.Read(fromBuf, binary.BigEndian, &elem.(*ru8).value)
        case RPCM_RU16:
            elem = &ru16{rElem: rElem{typ: RPCM_RU16}}
            err = binary.Read(fromBuf, binary.BigEndian, &elem.(*ru16).value)
        case RPCM_RU32:
            elem = &ru32{rElem: rElem{typ: RPCM_RU32}}
            err = binary.Read(fromBuf, binary.BigEndian, &elem.(*ru32).value)
        case RPCM_RU64:
            elem = &ru64{rElem: rElem{typ: RPCM_RU64}}
            err = binary.Read(fromBuf, binary.BigEndian, &elem.(*ru64).value)
        case RPCM_STRINGA:
            elem = &rStringA{rElem: rElem{typ: RPCM_STRINGA}}
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
                if elem.(*rStringA).value[len(elem.(*rStringA).value) - 1] == 0 {
                    elem.(*rStringA).value = elem.(*rStringA).value[0:len(elem.(*rStringA).value) - 1]
                }
            }
        case RPCM_STRINGW:
            elem = &rStringW{rElem: rElem{typ: RPCM_STRINGW}}
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
                if elem.(*rStringW).value[len(elem.(*rStringW).value) - 1] == 0 {
                    elem.(*rStringW).value = elem.(*rStringW).value[0:len(elem.(*rStringW).value) - 1]
                }
            }
        case RPCM_BUFFER:
            elem = &rBuffer{rElem: rElem{typ: RPCM_BUFFER}}
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
        case RPCM_TIMESTAMP:
            elem = &rTimestamp{rElem: rElem{typ: RPCM_TIMESTAMP}}
            err = binary.Read(fromBuf, binary.BigEndian, &elem.(*rTimestamp).value)
        case RPCM_IPV4:
            elem = &rIpv4{rElem: rElem{typ: RPCM_IPV4}}
            err = binary.Read(fromBuf, binary.BigEndian, &elem.(*rIpv4).value)
        case RPCM_IPV6:
            elem = &rIpv6{rElem: rElem{typ: RPCM_IPV6}}
            sizeRead, err = fromBuf.Read(elem.(*rIpv6).value[:])
            if uint32(sizeRead) != 16 {
                err = errors.New("Error reading enough data from buffer")
            }
        case RPCM_POINTER_32:
            elem = &rPointer32{rElem: rElem{typ: RPCM_POINTER_32}}
            err = binary.Read(fromBuf, binary.BigEndian, &elem.(*rPointer32).value)
        case RPCM_POINTER_64:
            elem = &rPointer64{rElem: rElem{typ: RPCM_POINTER_64}}
            err = binary.Read(fromBuf, binary.BigEndian, &elem.(*rPointer64).value)
        case RPCM_TIMEDELTA:
            elem = &rTimedelta{rElem: rElem{typ: RPCM_TIMEDELTA}}
            err = binary.Read(fromBuf, binary.BigEndian, &elem.(*rTimedelta).value)
        case RPCM_SEQUENCE:
            elem = &Sequence{rElem: rElem{typ: RPCM_SEQUENCE}, elements: make(map[uint32]rpcmElement)}
            err = elem.(*Sequence).Deserialize(fromBuf)
        case RPCM_LIST:
            elem = &List{rElem: rElem{typ: RPCM_LIST}}
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
func (this *Sequence) ToMachine() MachineSequence {
    j := make(map[uint32]interface{})

    for tag, val := range this.elements {
        if val.GetType() == RPCM_SEQUENCE {
            j[tag] = val.(*Sequence).ToMachine()
        } else if val.GetType() == RPCM_LIST {
            j[tag] = val.(*List).ToMachine()
        } else {
            j[tag] = val.GetValue()
        }
    }

    return j
}

func (this *List) ToMachine() MachineList {
    j := make([]interface{},0)
    
    for _, val := range this.elements {
        if val.GetType() == RPCM_SEQUENCE {
            j = append(j, val.(*Sequence).ToMachine())
        } else if val.GetType() == RPCM_LIST {
            j = append(j, val.(*List).ToMachine())
        } else {
            j = append(j, val.GetValue())
        }
    }

    return j
}

func (this *Sequence) ToJson() map[string]interface{} {
    var tagLabel string
    var ok bool

    j := make(map[string]interface{})

    for tag, val := range this.elements {
        if tagLabel, ok = HumanReadableTags[tag]; !ok {
            tagLabel = strconv.FormatUint(uint64(tag), 16)
        }

        if val.GetType() == RPCM_SEQUENCE {
            j[tagLabel] = val.(*Sequence).ToJson()
        } else if val.GetType() == RPCM_LIST {
            j[tagLabel] = val.(*List).ToJson()
        } else {
            j[tagLabel] = val.GetValue()
        }
    }

    return j
}

func (this *List) ToJson() []interface{} {
    j := make([]interface{},0)
    
    for _, val := range this.elements {
        if val.GetType() == RPCM_SEQUENCE {
            j = append(j, val.(*Sequence).ToJson())
        } else if val.GetType() == RPCM_LIST {
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
func (this *Sequence) AddInt8(tag uint32, number uint8) *Sequence {
    this.elements[tag] = &ru8{rElem: rElem{typ: RPCM_RU8}, value: number}
    return this
}

func (this *Sequence) AddInt16(tag uint32, number uint16) *Sequence {
    this.elements[tag] = &ru16{rElem: rElem{typ: RPCM_RU16}, value: number}
    return this
}

func (this *Sequence) AddInt32(tag uint32, number uint32) *Sequence {
    this.elements[tag] = &ru32{rElem: rElem{typ: RPCM_RU32}, value: number}
    return this
}

func (this *Sequence) AddInt64(tag uint32, number uint64) *Sequence {
    this.elements[tag] = &ru64{rElem: rElem{typ: RPCM_RU64}, value: number}
    return this
}

func (this *Sequence) AddStringA(tag uint32, str string) *Sequence {
    this.elements[tag] = &rStringA{rElem: rElem{typ: RPCM_STRINGA}, value: str}
    return this
}

func (this *Sequence) AddStringW(tag uint32, str string) *Sequence {
    this.elements[tag] = &rStringW{rElem: rElem{typ: RPCM_STRINGW}, value: str}
    return this
}

func (this *Sequence) AddBuffer(tag uint32, buf []byte) *Sequence {
    this.elements[tag] = &rBuffer{rElem: rElem{typ: RPCM_BUFFER}, value: buf}
    return this
}

func (this *Sequence) AddTimestamp(tag uint32, ts uint64) *Sequence {
    this.elements[tag] = &rTimestamp{rElem: rElem{typ: RPCM_TIMESTAMP}, value: ts}
    return this
}

func (this *Sequence) AddIpv4(tag uint32, ip4 uint32) *Sequence {
    this.elements[tag] = &rIpv4{rElem: rElem{typ: RPCM_IPV4}, value: ip4}
    return this
}

func (this *Sequence) AddIpv6(tag uint32, ip6 [16]byte) *Sequence {
    this.elements[tag] = &rIpv6{rElem: rElem{typ: RPCM_IPV6}, value: ip6}
    return this
}

func (this *Sequence) AddPointer32(tag uint32, ptr uint32) *Sequence {
    this.elements[tag] = &rPointer32{rElem: rElem{typ: RPCM_POINTER_32}, value: ptr}
    return this
}

func (this *Sequence) AddPointer64(tag uint32, ptr uint64) *Sequence {
    this.elements[tag] = &rPointer64{rElem: rElem{typ: RPCM_POINTER_64}, value: ptr}
    return this
}

func (this *Sequence) AddTimesdelta(tag uint32, td uint64) *Sequence {
    this.elements[tag] = &rTimedelta{rElem: rElem{typ: RPCM_TIMEDELTA}, value: td}
    return this
}

func (this *Sequence) AddSequence(tag uint32, seq *Sequence) *Sequence {
    seq.typ = RPCM_SEQUENCE
    this.elements[tag] = seq
    return this
}

func (this *Sequence) AddList(tag uint32, list *List) *Sequence {
    list.typ = RPCM_LIST
    this.elements[tag] = list
    return this
}

func (this *Sequence) GetInt8(tag uint32) (uint8, bool) {
    var res uint8
    var ok bool

    if elem, found := this.elements[tag]; found && elem.GetType() == RPCM_RU8 {
        ok = true
        res = elem.(*ru8).value
    }

    return res, ok
}

func (this *Sequence) GetInt16(tag uint32) (uint16, bool) {
    var res uint16
    var ok bool

    if elem, found := this.elements[tag]; found && elem.GetType() == RPCM_RU16 {
        ok = true
        res = elem.(*ru16).value
    }

    return res, ok
}

func (this *Sequence) GetInt32(tag uint32) (uint32, bool) {
    var res uint32
    var ok bool

    if elem, found := this.elements[tag]; found && elem.GetType() == RPCM_RU32 {
        ok = true
        res = elem.(*ru32).value
    }

    return res, ok
}

func (this *Sequence) GetInt64(tag uint32) (uint64, bool) {
    var res uint64
    var ok bool

    if elem, found := this.elements[tag]; found && elem.GetType() == RPCM_RU64 {
        ok = true
        res = elem.(*ru64).value
    }

    return res, ok
}

func (this *Sequence) GetStringA(tag uint32) (string, bool) {
    var res string
    var ok bool

    if elem, found := this.elements[tag]; found && elem.GetType() == RPCM_STRINGA {
        ok = true
        res = elem.(*rStringA).value
    }

    return res, ok
}

func (this *Sequence) GetStringW(tag uint32) (string, bool) {
    var res string
    var ok bool

    if elem, found := this.elements[tag]; found && elem.GetType() == RPCM_STRINGW {
        ok = true
        res = elem.(*rStringW).value
    }

    return res, ok
}

func (this *Sequence) GetBuffer(tag uint32) ([]byte, bool) {
    var res []byte
    var ok bool

    if elem, found := this.elements[tag]; found && elem.GetType() == RPCM_BUFFER {
        ok = true
        res = elem.(*rBuffer).value
    }

    return res, ok
}

func (this *Sequence) GetTimestamp(tag uint32) (uint64, bool) {
    var res uint64
    var ok bool

    if elem, found := this.elements[tag]; found && elem.GetType() == RPCM_TIMESTAMP {
        ok = true
        res = elem.(*rTimestamp).value
    }

    return res, ok
}

func (this *Sequence) GetIpv4(tag uint32) (uint32, bool) {
    var res uint32
    var ok bool

    if elem, found := this.elements[tag]; found && elem.GetType() == RPCM_IPV4 {
        ok = true
        res = elem.(*rIpv4).value
    }

    return res, ok
}

func (this *Sequence) GetIpv6(tag uint32) ([16]byte, bool) {
    var res [16]byte
    var ok bool

    if elem, found := this.elements[tag]; found && elem.GetType() == RPCM_IPV6 {
        ok = true
        res = elem.(*rIpv6).value
    }

    return res, ok
}

func (this *Sequence) GetPointer32(tag uint32) (uint32, bool) {
    var res uint32
    var ok bool

    if elem, found := this.elements[tag]; found && elem.GetType() == RPCM_POINTER_32 {
        ok = true
        res = elem.(*rPointer32).value
    }

    return res, ok
}

func (this *Sequence) GetPointer64(tag uint32) (uint64, bool) {
    var res uint64
    var ok bool

    if elem, found := this.elements[tag]; found && elem.GetType() == RPCM_POINTER_64 {
        ok = true
        res = elem.(*rPointer64).value
    }

    return res, ok
}

func (this *Sequence) GetTimedelta(tag uint32) (uint64, bool) {
    var res uint64
    var ok bool

    if elem, found := this.elements[tag]; found && elem.GetType() == RPCM_TIMEDELTA {
        ok = true
        res = elem.(*rTimedelta).value
    }

    return res, ok
}

func (this *Sequence) GetSequence(tag uint32) (*Sequence, bool) {
    var res *Sequence
    var ok bool

    if elem, found := this.elements[tag]; found && elem.GetType() == RPCM_SEQUENCE {
        ok = true
        res = elem.(*Sequence)
    }

    return res, ok
}

func (this *Sequence) GetList(tag uint32) (*List, bool) {
    var res *List
    var ok bool

    if elem, found := this.elements[tag]; found && elem.GetType() == RPCM_LIST {
        ok = true
        res = elem.(*List)
    }

    return res, ok
}

//=============================================================================
// List
//=============================================================================
func (this *List) AddInt8(number uint8) *List {
    if this.elemType == RPCM_RU8 {
        this.elements = append(this.elements, &ru8{rElem: rElem{typ: RPCM_RU8}, value: number})
        return this
    }
    return nil
}

func (this *List) AddInt16(number uint16) *List {
    if this.elemType == RPCM_RU16 {
        this.elements = append(this.elements, &ru16{rElem: rElem{typ: RPCM_RU16}, value: number})
        return this
    }
    return nil
}

func (this *List) AddInt32(number uint32) *List {
    if this.elemType == RPCM_RU32 {
        this.elements = append(this.elements, &ru32{rElem: rElem{typ: RPCM_RU32}, value: number})
        return this
    }
    return nil
}

func (this *List) AddInt64(number uint64) *List {
    if this.elemType == RPCM_RU64 {
        this.elements = append(this.elements, &ru64{rElem: rElem{typ: RPCM_RU64}, value: number})
        return this
    }
    return nil
}

func (this *List) AddStringA(str string) *List {
    if this.elemType == RPCM_STRINGA {
        this.elements = append(this.elements, &rStringA{rElem: rElem{typ: RPCM_STRINGA}, value: str})
        return this
    }
    return nil
}

func (this *List) AddStringW(str string) *List {
    if this.elemType == RPCM_STRINGW {
        this.elements = append(this.elements, &rStringW{rElem: rElem{typ: RPCM_STRINGW}, value: str})
        return this
    }
    return nil
}

func (this *List) AddBuffer(buf []byte) *List {
    if this.elemType == RPCM_BUFFER {
        this.elements = append(this.elements, &rBuffer{rElem: rElem{typ: RPCM_BUFFER}, value: buf})
        return this
    }
    return nil
}

func (this *List) AddTimestamp(ts uint64) *List {
    if this.elemType == RPCM_TIMESTAMP {
        this.elements = append(this.elements, &rTimestamp{rElem: rElem{typ: RPCM_TIMESTAMP}, value: ts})
        return this
    }
    return nil
}

func (this *List) AddIpv4(ip4 uint32) *List {
    if this.elemType == RPCM_IPV4 {
        this.elements = append(this.elements, &rIpv4{rElem: rElem{typ: RPCM_IPV4}, value: ip4})
        return this
    }
    return nil
}

func (this *List) AddIpv6(ip6 [16]byte) *List {
    if this.elemType == RPCM_IPV6 {
        this.elements = append(this.elements, &rIpv6{rElem: rElem{typ: RPCM_IPV6}, value: ip6})
        return this
    }
    return nil
}

func (this *List) AddPointer32(ptr uint32) *List {
    if this.elemType == RPCM_POINTER_32 {
        this.elements = append(this.elements, &rPointer32{rElem: rElem{typ: RPCM_POINTER_32}, value: ptr})
        return this
    }
    return nil
}

func (this *List) AddPointer64(ptr uint64) *List {
    if this.elemType == RPCM_POINTER_64 {
        this.elements = append(this.elements, &rPointer64{rElem: rElem{typ: RPCM_POINTER_64}, value: ptr})
        return this
    }
    return nil
}

func (this *List) AddTimesdelta(td uint64) *List {
    if this.elemType == RPCM_TIMEDELTA {
        this.elements = append(this.elements, &rTimedelta{rElem: rElem{typ: RPCM_TIMEDELTA}, value: td})
        return this
    }
    return nil
}

func (this *List) AddSequence(seq *Sequence) *List {
    if this.elemType == RPCM_SEQUENCE {
        seq.typ = RPCM_SEQUENCE
        this.elements = append(this.elements, seq)
        return this
    }
    return nil
}

func (this *List) AddList(list *List) *List {
    if this.elemType == RPCM_LIST {
        list.typ = RPCM_LIST
        this.elements = append(this.elements, list)
        return this
    }
    return nil
}

func (this *List) GetInt8(tag uint32) (uint8, bool) {
    var res uint8
    var ok bool

    if RPCM_RU8 == this.elemType && tag == this.elemTag {
        if this.iterator > len(this.elements) {
            this.iterator = 0
        } else {
            ok = true
            res = this.elements[this.iterator].(*ru8).value
        }
    }

    return res, ok
}

func (this *List) GetInt16(tag uint32) (uint16, bool) {
    var res uint16
    var ok bool

    if RPCM_RU16 == this.elemType && tag == this.elemTag {
        if this.iterator > len(this.elements) {
            this.iterator = 0
        } else {
            ok = true
            res = this.elements[this.iterator].(*ru16).value
        }
    }

    return res, ok
}

func (this *List) GetInt32(tag uint32) (uint32, bool) {
    var res uint32
    var ok bool

    if RPCM_RU32 == this.elemType && tag == this.elemTag {
        if this.iterator > len(this.elements) {
            this.iterator = 0
        } else {
            ok = true
            res = this.elements[this.iterator].(*ru32).value
        }
    }

    return res, ok
}

func (this *List) GetInt64(tag uint32) (uint64, bool) {
    var res uint64
    var ok bool

    if RPCM_RU64 == this.elemType && tag == this.elemTag {
        if this.iterator > len(this.elements) {
            this.iterator = 0
        } else {
            ok = true
            res = this.elements[this.iterator].(*ru64).value
        }
    }

    return res, ok
}

func (this *List) GetStringA(tag uint32) (string, bool) {
    var res string
    var ok bool

    if RPCM_STRINGA == this.elemType && tag == this.elemTag {
        if this.iterator > len(this.elements) {
            this.iterator = 0
        } else {
            ok = true
            res = this.elements[this.iterator].(*rStringA).value
        }
    }

    return res, ok
}

func (this *List) GetStringW(tag uint32) (string, bool) {
    var res string
    var ok bool

    if RPCM_STRINGW == this.elemType && tag == this.elemTag {
        if this.iterator > len(this.elements) {
            this.iterator = 0
        } else {
            ok = true
            res = this.elements[this.iterator].(*rStringW).value
        }
    }

    return res, ok
}

func (this *List) GetBuffer(tag uint32) ([]byte, bool) {
    var res []byte
    var ok bool

    if RPCM_BUFFER == this.elemType && tag == this.elemTag {
        if this.iterator > len(this.elements) {
            this.iterator = 0
        } else {
            ok = true
            res = this.elements[this.iterator].(*rBuffer).value
        }
    }

    return res, ok
}

func (this *List) GetTimestamp(tag uint32) (uint64, bool) {
    var res uint64
    var ok bool

    if RPCM_TIMESTAMP == this.elemType && tag == this.elemTag {
        if this.iterator > len(this.elements) {
            this.iterator = 0
        } else {
            ok = true
            res = this.elements[this.iterator].(*rTimestamp).value
        }
    }

    return res, ok
}

func (this *List) GetIpv4(tag uint32) (uint32, bool) {
    var res uint32
    var ok bool

    if RPCM_IPV4 == this.elemType && tag == this.elemTag {
        if this.iterator > len(this.elements) {
            this.iterator = 0
        } else {
            ok = true
            res = this.elements[this.iterator].(*rIpv4).value
        }
    }

    return res, ok
}

func (this *List) GetIpv6(tag uint32) ([16]byte, bool) {
    var res [16]byte
    var ok bool

    if RPCM_IPV6 == this.elemType && tag == this.elemTag {
        if this.iterator > len(this.elements) {
            this.iterator = 0
        } else {
            ok = true
            res = this.elements[this.iterator].(*rIpv6).value
        }
    }

    return res, ok
}

func (this *List) GetPointer32(tag uint32) (uint32, bool) {
    var res uint32
    var ok bool

    if RPCM_POINTER_32 == this.elemType && tag == this.elemTag {
        if this.iterator > len(this.elements) {
            this.iterator = 0
        } else {
            ok = true
            res = this.elements[this.iterator].(*rPointer32).value
        }
    }

    return res, ok
}

func (this *List) GetPointer64(tag uint32) (uint64, bool) {
    var res uint64
    var ok bool

    if RPCM_POINTER_64 == this.elemType && tag == this.elemTag {
        if this.iterator > len(this.elements) {
            this.iterator = 0
        } else {
            ok = true
            res = this.elements[this.iterator].(*rPointer64).value
        }
    }

    return res, ok
}

func (this *List) GetTimedelta(tag uint32) (uint64, bool) {
    var res uint64
    var ok bool

    if RPCM_TIMEDELTA == this.elemType && tag == this.elemTag {
        if this.iterator > len(this.elements) {
            this.iterator = 0
        } else {
            ok = true
            res = this.elements[this.iterator].(*rTimedelta).value
        }
    }

    return res, ok
}

func (this *List) GetSequence(tag uint32) (*Sequence, bool) {
    var res *Sequence
    var ok bool

    if RPCM_SEQUENCE == this.elemType && tag == this.elemTag {
        if this.iterator > len(this.elements) {
            this.iterator = 0
        } else {
            ok = true
            res = this.elements[this.iterator].(*Sequence)
        }
    }

    return res, ok
}

func (this *List) GetList(tag uint32) (*List, bool) {
    var res *List
    var ok bool

    if RPCM_LIST == this.elemType && tag == this.elemTag {
        if this.iterator > len(this.elements) {
            this.iterator = 0
        } else {
            ok = true
            res = this.elements[this.iterator].(*List)
        }
    }

    return res, ok
}
