package main

import "fmt"

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
