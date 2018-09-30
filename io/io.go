package io

import (
	"context"
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
