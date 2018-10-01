package io

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

func ReadFull(conn net.Conn, buf []byte) error {
	if n, err := io.ReadFull(conn, buf); err != nil {
		return err
	} else if n < len(buf) {
		return fmt.Errorf("received %d bytes but got %d", n, len(buf))
	}
	return nil
}

func CopyInChunks(ctx context.Context, dst io.Writer, src io.Reader, total uint64, blocksize uint64, hook func(transferred uint64)) (uint64, error) {
	transferred := uint64(0)
	for transferred < total {
		select {
		case <-ctx.Done():
			return transferred, ctx.Err()
		default:
		}

		block := blocksize
		if total-transferred < blocksize {
			block = total - transferred
		}

		n, err := io.CopyN(dst, src, int64(block))
		transferred += uint64(n)
		if err != nil {
			return transferred, err
		}

		hook(transferred)
	}
	return transferred, nil
}

func ReadUInt64(r io.Reader) (uint64, error) {
	buf := new(bytes.Buffer)
	if _, err := io.CopyN(buf, r, 8); err != nil {
		return 0, fmt.Errorf("read uint64: %v", err)
	}
	return binary.BigEndian.Uint64(buf.Bytes()), nil
}

func WriteUInt64(w io.Writer, n uint64) error {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, n)
	if _, err := io.CopyN(w, bytes.NewReader(buf), 8); err != nil {
		return fmt.Errorf("write uint64: %v", err)
	}
	return nil
}
