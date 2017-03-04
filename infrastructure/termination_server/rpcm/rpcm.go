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

type rSequence struct {
    rElem
    elements map[uint32]rpcmElement
}

type rList struct {
    rElem
    elemTag uint32
    elemType uint8
    elements []rpcmElement
}

func (this *rElem) GetType() uint8 {
    return this.typ
}

//=============================================================================
// Constructors
//=============================================================================
func Sequence() *rSequence {
    return &rSequence{rElem: rElem{RPCM_SEQUENCE}, elements: make(map[uint32]rpcmElement)}
}

func List(elemTag uint32, elemType uint8) *rList {
    return &rList{rElem: rElem{RPCM_LIST}, elemTag : elemTag, elemType : elemType}
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

func (this *rSequence) Serialize(toBuf *bytes.Buffer) error {
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

func (this *rList) Serialize(toBuf *bytes.Buffer) error {
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
func (this *rSequence)Deserialize(fromBuf *bytes.Buffer) error {
    var nElements uint32
    var tag uint32
    var typ uint8

    this.typ = RPCM_SEQUENCE

    err := binary.Read(fromBuf, binary.BigEndian, &nElements)
    if err != nil {
        return err
    }

    for i := uint32(0); i < nElements; i++ {
        err = binary.Read(fromBuf, binary.BigEndian, &tag)
        if err != nil {
            return err
        }
        err = binary.Read(fromBuf, binary.BigEndian, &typ)
        if err != nil {
            return err
        }
        tmpElem := rpcmDeserializeElem(fromBuf, typ)
        if tmpElem == nil {
            return errors.New("Failed to deserialize an element.")
        }

        this.elements[tag] = tmpElem
    }

    return err
}

func (this *rList)Deserialize(fromBuf *bytes.Buffer) error {
    var nElements uint32
    var tag uint32
    var typ uint8

    this.typ = RPCM_SEQUENCE

    err := binary.Read(fromBuf, binary.BigEndian, &this.elemTag)
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
        tmpElem := rpcmDeserializeElem(fromBuf, typ)
        if tmpElem == nil {
            return errors.New("Failed to deserialize an element.")
        }

        this.elements = append(this.elements, tmpElem)
    }

    return err
}

func rpcmDeserializeElem(fromBuf *bytes.Buffer, typ uint8) rpcmElement {
    var elem rpcmElement = nil
    var elemLen uint32
    var tmpBuf []byte
    var err error
    
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
            tmpBuf = make([]byte, elemLen)
            _, err = fromBuf.Read(tmpBuf)
            if err == nil {
                elem.(*rStringA).value = string(tmpBuf)
            }
        case RPCM_STRINGW:
            elem = &rStringW{rElem: rElem{typ: RPCM_STRINGW}}
            err = binary.Read(fromBuf, binary.BigEndian, &elemLen)
            tmpBuf = make([]byte, elemLen)
            _, err = fromBuf.Read(tmpBuf)
            if err == nil {
                elem.(*rStringW).value = string(tmpBuf)
            }
        case RPCM_BUFFER:
            elem = &rBuffer{rElem: rElem{typ: RPCM_BUFFER}}
            err = binary.Read(fromBuf, binary.BigEndian, &elemLen)
            tmpBuf = make([]byte, elemLen)
            _, err = fromBuf.Read(tmpBuf)
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
            _, err = fromBuf.Read(elem.(*rIpv6).value[:])
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
            elem = &rSequence{rElem: rElem{typ: RPCM_SEQUENCE}, elements: make(map[uint32]rpcmElement)}
            err = elem.(*rSequence).Deserialize(fromBuf)
        case RPCM_LIST:
            elem = &rList{rElem: rElem{typ: RPCM_LIST}}
            err = elem.(*rList).Deserialize(fromBuf)
        default:
            elem = nil
    }

    if err != nil {
        elem = nil
    }

    return elem
}

//=============================================================================
// Format Change
//=============================================================================
func (this *rSequence) ToMachine() map[uint32]interface{} {
    j := make(map[uint32]interface{})

    for tag, val := range this.elements {
        if val.GetType() == RPCM_SEQUENCE {
            j[tag] = val.(*rSequence).ToMachine()
        } else if val.GetType() == RPCM_LIST {
            j[tag] = val.(*rList).ToMachine()
        } else {
            j[tag] = val
        }
    }

    return j
}

func (this *rList) ToMachine() []interface{} {
    j := make([]interface{},0)
    
    for _, val := range this.elements {
        if val.GetType() == RPCM_SEQUENCE {
            j = append(j, val.(*rSequence).ToMachine())
        } else if val.GetType() == RPCM_LIST {
            j = append(j, val.(*rList).ToMachine())
        } else {
            j = append(j, val)
        }
    }

    return j
}

func (this *rSequence) ToJson() map[string]interface{} {
    var tagLabel string
    var ok bool

    j := make(map[string]interface{})

    for tag, val := range this.elements {
        if tagLabel, ok = HumanReadableTags[tag]; !ok {
            tagLabel = strconv.FormatUint(uint64(tag), 16)
        }

        if val.GetType() == RPCM_SEQUENCE {
            j[tagLabel] = val.(*rSequence).ToJson()
        } else if val.GetType() == RPCM_LIST {
            j[tagLabel] = val.(*rList).ToJson()
        } else {
            j[tagLabel] = val
        }
    }

    return j
}

func (this *rList) ToJson() []interface{} {
    j := make([]interface{},0)
    
    for _, val := range this.elements {
        if val.GetType() == RPCM_SEQUENCE {
            j = append(j, val.(*rSequence).ToJson())
        } else if val.GetType() == RPCM_LIST {
            j = append(j, val.(*rList).ToJson())
        } else {
            j = append(j, val)
        }
    }

    return j
}

//=============================================================================
// Sequence
//=============================================================================
func (this *rSequence) AddInt8(tag uint32, number uint8) *rSequence {
    this.elements[tag] = &ru8{rElem: rElem{typ: RPCM_RU8}, value: number}
    return this
}

func (this *rSequence) AddInt16(tag uint32, number uint16) *rSequence {
    this.elements[tag] = &ru16{rElem: rElem{typ: RPCM_RU16}, value: number}
    return this
}

func (this *rSequence) AddInt32(tag uint32, number uint32) *rSequence {
    this.elements[tag] = &ru32{rElem: rElem{typ: RPCM_RU32}, value: number}
    return this
}

func (this *rSequence) AddInt64(tag uint32, number uint64) *rSequence {
    this.elements[tag] = &ru64{rElem: rElem{typ: RPCM_RU64}, value: number}
    return this
}

func (this *rSequence) AddStringA(tag uint32, str string) *rSequence {
    this.elements[tag] = &rStringA{rElem: rElem{typ: RPCM_STRINGA}, value: str}
    return this
}

func (this *rSequence) AddStringW(tag uint32, str string) *rSequence {
    this.elements[tag] = &rStringW{rElem: rElem{typ: RPCM_STRINGW}, value: str}
    return this
}

func (this *rSequence) AddBuffer(tag uint32, buf []byte) *rSequence {
    this.elements[tag] = &rBuffer{rElem: rElem{typ: RPCM_BUFFER}, value: buf}
    return this
}

func (this *rSequence) AddTimestamp(tag uint32, ts uint64) *rSequence {
    this.elements[tag] = &rTimestamp{rElem: rElem{typ: RPCM_TIMESTAMP}, value: ts}
    return this
}

func (this *rSequence) AddIpv4(tag uint32, ip4 uint32) *rSequence {
    this.elements[tag] = &rIpv4{rElem: rElem{typ: RPCM_IPV4}, value: ip4}
    return this
}

func (this *rSequence) AddIpv6(tag uint32, ip6 [16]byte) *rSequence {
    this.elements[tag] = &rIpv6{rElem: rElem{typ: RPCM_IPV6}, value: ip6}
    return this
}

func (this *rSequence) AddPointer32(tag uint32, ptr uint32) *rSequence {
    this.elements[tag] = &rPointer32{rElem: rElem{typ: RPCM_POINTER_32}, value: ptr}
    return this
}

func (this *rSequence) AddPointer64(tag uint32, ptr uint64) *rSequence {
    this.elements[tag] = &rPointer64{rElem: rElem{typ: RPCM_POINTER_64}, value: ptr}
    return this
}

func (this *rSequence) AddTimesdelta(tag uint32, td uint64) *rSequence {
    this.elements[tag] = &rTimedelta{rElem: rElem{typ: RPCM_TIMEDELTA}, value: td}
    return this
}

func (this *rSequence) AddSequence(tag uint32, seq *rSequence) *rSequence {
    seq.typ = RPCM_SEQUENCE
    this.elements[tag] = seq
    return this
}

func (this *rSequence) AddList(tag uint32, list *rList) *rSequence {
    list.typ = RPCM_LIST
    this.elements[tag] = list
    return this
}

//=============================================================================
// List
//=============================================================================
func (this *rList) AddInt8(tag uint32, number uint8) *rList {
    if this.elemType == RPCM_RU8 {
        this.elements[tag] = &ru8{rElem: rElem{typ: RPCM_RU8}, value: number}
        return this
    }
    return nil
}

func (this *rList) AddInt16(tag uint32, number uint16) *rList {
    if this.elemType == RPCM_RU16 {
        this.elements[tag] = &ru16{rElem: rElem{typ: RPCM_RU16}, value: number}
        return this
    }
    return nil
}

func (this *rList) AddInt32(tag uint32, number uint32) *rList {
    if this.elemType == RPCM_RU32 {
        this.elements[tag] = &ru32{rElem: rElem{typ: RPCM_RU32}, value: number}
        return this
    }
    return nil
}

func (this *rList) AddInt64(tag uint32, number uint64) *rList {
    if this.elemType == RPCM_RU64 {
        this.elements[tag] = &ru64{rElem: rElem{typ: RPCM_RU64}, value: number}
        return this
    }
    return nil
}

func (this *rList) AddStringA(tag uint32, str string) *rList {
    if this.elemType == RPCM_STRINGA {
        this.elements[tag] = &rStringA{rElem: rElem{typ: RPCM_STRINGA}, value: str}
        return this
    }
    return nil
}

func (this *rList) AddStringW(tag uint32, str string) *rList {
    if this.elemType == RPCM_STRINGW {
        this.elements[tag] = &rStringW{rElem: rElem{typ: RPCM_STRINGW}, value: str}
        return this
    }
    return nil
}

func (this *rList) AddBuffer(tag uint32, buf []byte) *rList {
    if this.elemType == RPCM_BUFFER {
        this.elements[tag] = &rBuffer{rElem: rElem{typ: RPCM_BUFFER}, value: buf}
        return this
    }
    return nil
}

func (this *rList) AddTimestamp(tag uint32, ts uint64) *rList {
    if this.elemType == RPCM_TIMESTAMP {
        this.elements[tag] = &rTimestamp{rElem: rElem{typ: RPCM_TIMESTAMP}, value: ts}
        return this
    }
    return nil
}

func (this *rList) AddIpv4(tag uint32, ip4 uint32) *rList {
    if this.elemType == RPCM_IPV4 {
        this.elements[tag] = &rIpv4{rElem: rElem{typ: RPCM_IPV4}, value: ip4}
        return this
    }
    return nil
}

func (this *rList) AddIpv6(tag uint32, ip6 [16]byte) *rList {
    if this.elemType == RPCM_IPV6 {
        this.elements[tag] = &rIpv6{rElem: rElem{typ: RPCM_IPV6}, value: ip6}
        return this
    }
    return nil
}

func (this *rList) AddPointer32(tag uint32, ptr uint32) *rList {
    if this.elemType == RPCM_POINTER_32 {
        this.elements[tag] = &rPointer32{rElem: rElem{typ: RPCM_POINTER_32}, value: ptr}
        return this
    }
    return nil
}

func (this *rList) AddPointer64(tag uint32, ptr uint64) *rList {
    if this.elemType == RPCM_POINTER_64 {
        this.elements[tag] = &rPointer64{rElem: rElem{typ: RPCM_POINTER_64}, value: ptr}
        return this
    }
    return nil
}

func (this *rList) AddTimesdelta(tag uint32, td uint64) *rList {
    if this.elemType == RPCM_TIMEDELTA {
        this.elements[tag] = &rTimedelta{rElem: rElem{typ: RPCM_TIMEDELTA}, value: td}
        return this
    }
    return nil
}

func (this *rList) AddSequence(tag uint32, seq *rSequence) *rList {
    if this.elemType == RPCM_SEQUENCE {
        seq.typ = RPCM_SEQUENCE
        this.elements = append(this.elements, seq)
        return this
    }
    return nil
}

func (this *rList) AddList(tag uint32, list *rList) *rList {
    if this.elemType == RPCM_LIST {
        list.typ = RPCM_LIST
        this.elements = append(this.elements, list)
        return this
    }
    return nil
}

