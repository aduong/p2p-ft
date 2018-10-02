package proto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	FilenameSize      = 256
	contentLengthSize = 8 // 8 bytes = 64 bits for uint64
	sendFlagsSize     = 1 // single byte
	requestToSendSize = FilenameSize + contentLengthSize + sha256.Size + sendFlagsSize
)

type RequestToSend struct {
	Filename      string
	ContentLength uint64
	SHA256sum     [sha256.Size]byte
}

func (r *RequestToSend) ToBytes() ([requestToSendSize]byte, error) {
	if len(r.Filename) > FilenameSize {
		return [requestToSendSize]byte{}, fmt.Errorf("create req: filename exceeds 256 bytes")
	}

	offset := 0
	var data [requestToSendSize]byte

	copy(data[offset:offset+FilenameSize], []byte(r.Filename))
	offset += FilenameSize

	binary.BigEndian.PutUint64(data[offset:offset+contentLengthSize], r.ContentLength)
	offset += contentLengthSize

	copy(data[offset:offset+sha256.Size], r.SHA256sum[:])
	offset += sha256.Size

	var flags byte
	copy(data[offset:offset+sendFlagsSize], []byte{flags})
	offset += sendFlagsSize

	return data, nil
}

func (r *RequestToSend) FromBytes(data []byte) error {
	if len(data) < requestToSendSize {
		return fmt.Errorf("read request: received %d byte but expected %d bytes", len(data), requestToSendSize)
	}
	offset := 0

	r.Filename = strings.TrimRight(string(data[offset : offset+FilenameSize]), "\x00")
	offset += FilenameSize

	r.ContentLength = binary.BigEndian.Uint64(data[offset : offset+contentLengthSize])
	offset += contentLengthSize

	copy(r.SHA256sum[:], data[offset:offset+sha256.Size])
	offset += sha256.Size

	_ = data[offset : offset+sendFlagsSize][0]
	offset += sendFlagsSize

	return nil
}

func (r *RequestToSend) Send(conn net.Conn) error {
	data, err := r.ToBytes()
	if err != nil {
		return err
	}
	if _, err := io.Copy(conn, bytes.NewReader(data[:])); err != nil {
		return fmt.Errorf("send request: %v", err)
	}
	return nil
}

func (r *RequestToSend) Read(conn net.Conn) error {
	data := make([]byte, requestToSendSize)
	if _, err := io.ReadFull(conn, data); err != nil {
		return fmt.Errorf("read request: %v", err)
	}

	if err := r.FromBytes(data); err != nil {
		return err
	}

	return nil
}

const (
	offsetSize           = 8 // 8 bytes = 64 bits for uint64
	receiveFlagsSize     = 1
	requestToReceiveSize = offsetSize + receiveFlagsSize
)

type RequestToReceive struct {
	Offset  uint64
	Proceed bool
}

func (r *RequestToReceive) ToBytes() [requestToReceiveSize]byte {
	offset := 0
	var data [requestToReceiveSize]byte

	binary.BigEndian.PutUint64(data[offset:offset+offsetSize], r.Offset)
	offset += offsetSize

	var flags byte
	if r.Proceed {
		flags = 1
	}
	copy(data[offset:offset+receiveFlagsSize], []byte{flags})
	offset += receiveFlagsSize

	return data
}

func (r *RequestToReceive) FromBytes(data []byte) error {
	if len(data) < requestToReceiveSize {
		return fmt.Errorf("read req: expected %d bytes but got %d bytes", requestToReceiveSize, len(data))
	}

	offset := 0

	r.Offset = binary.BigEndian.Uint64(data[offset : offset+offsetSize])
	offset += offsetSize

	flags := data[offset : offset+receiveFlagsSize][0]
	r.Proceed = flags&1 == 1
	offset += receiveFlagsSize

	return nil
}

func (r *RequestToReceive) Send(conn net.Conn) error {
	data := r.ToBytes()
	if _, err := io.Copy(conn, bytes.NewReader(data[:])); err != nil {
		return fmt.Errorf("send req: %v", err)
	}
	return nil
}

func (r *RequestToReceive) Read(conn net.Conn) error {
	data := make([]byte, requestToReceiveSize)
	if _, err := io.ReadFull(conn, data); err != nil {
		return fmt.Errorf("read req: %v", err)
	}
	return r.FromBytes(data)
}
