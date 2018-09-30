package main

import (
	"fmt"
	"io"
	"net"

	"context"

	"go.uber.org/zap"
)

const BlockSize uint64 = 1024 * 1024 // 1 MB
const P2PServiceType = "_adrp2p._tcp"

const FilenameSize = 256
const ContentLengthSize = 8 // 8 bytes = 64 bits for uint64

var suffixes = []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}

func prettySize(x uint64) (string, string) {
	i := 0
	mx := uint64(0)
	for x > 1024 && i < len(suffixes) {
		i++
		x, mx = x/1024, x%1024
	}

	if mx >= 512 {
		x += 1
	}
	return fmt.Sprintf("%d", x), suffixes[i]
}

func readFull(conn net.Conn, buf []byte) error {
	if n, err := io.ReadFull(conn, buf); err != nil {
		return err
	} else if n < len(buf) {
		return fmt.Errorf("received %d bytes but got %d", n, len(buf))
	}
	return nil
}

func copyInChunks(ctx context.Context, dst io.Writer, src io.Reader, total uint64, blocksize uint64, hook func(transferred uint64)) (uint64, error) {
	transferred := uint64(0)
	for transferred < total {
		select {
		case <-ctx.Done():
			return transferred, ctx.Err()
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

func createLogger() *zap.Logger {
	cfg := zap.NewDevelopmentConfig()
	l, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	return l
}
