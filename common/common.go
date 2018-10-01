package common

import (
	"fmt"

	"go.uber.org/zap"
)

const BlockSize uint64 = 1024 * 1024 // 1 MB
const P2PServiceType = "_adrp2p._tcp"

const FilenameSize = 256
const ContentLengthSize = 8 // 8 bytes = 64 bits for uint64

var suffixes = []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}

func PrettySize(x uint64) (string, string) {
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

func CreateLogger() *zap.Logger {
	cfg := zap.NewDevelopmentConfig()
	l, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	return l
}

func EqualBytes(b1, b2 []byte) bool {
	if len(b1) != len(b2) {
		return false
	}
	for i, _ := range b1 {
		if b1[i] != b2[i] {
			return false
		}
	}
	return true
}