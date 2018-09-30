package main

import (
	"fmt"
	"time"
	"io"
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
		x, mx = x / 1024, x % 1024
	}

	if mx >= 512 {
		x += 1
	}
	return fmt.Sprintf("%d", x), suffixes[i]
}

func copyInChunks(dst io.Writer, src io.Reader, filesize uint64, blocksize uint64) (uint64, error) {
	received := uint64(0)
	startTime := time.Now()
	for received < filesize {
		block := blocksize
		if filesize-received < blocksize {
			block = filesize - received
		}
		n, err := io.CopyN(dst, src, int64(block))
		received += uint64(n)
		if err != nil {
			return received, err
		}
		fmt.Printf("%d / %d (%d%%) %d seconds elapsed\n",
			received, filesize, 100*received/filesize, time.Now().Unix()-startTime.Unix())
	}
	return filesize, nil
}