package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/grandcat/zeroconf"
)

const BlockSize uint64 = 1024 * 1024 // 1 MB

func main () {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{})
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	defer listener.Close()
	localAddr := listener.Addr().(*net.TCPAddr)

	uuid, _ := uuid.NewUUID()
	server, err := zeroconf.Register(uuid.String(), P2PServiceType, "local.", localAddr.Port, nil, nil)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	defer server.Shutdown()

	fmt.Printf("Service %s listening at %v\n", uuid.String(), localAddr)

	stdinReader := bufio.NewReader(os.Stdin)
	empty := make([]byte, 256)
	filenameBytes := make([]byte, 256)
	contentLengthArr := make([]byte, 8)
	for {
		copy(filenameBytes, empty)

		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("err: %v\n", err)
			break
		}
		fmt.Printf("# accepted connection\n")

		if n, err := io.ReadFull(conn, filenameBytes); err != nil {
			fmt.Printf("err: %v\n", err)
			break
		} else if n < len(filenameBytes) {
			err := fmt.Errorf("expected %d bytes", len(filenameBytes))
			fmt.Printf("err: %v\n", err)
			break
		}
		filename := strings.TrimRight(string(filenameBytes), "\x00")
		fmt.Printf("filename=%s\n", filename)

		if n, err := io.ReadFull(conn, contentLengthArr); err != nil {
			fmt.Printf("err: %v\n", err)
			break
		} else if n < len(contentLengthArr) {
			err := fmt.Errorf("expected %d bytes", len(contentLengthArr))
			fmt.Printf("err: %v\n", err)
			break
		}
		size := binary.BigEndian.Uint64(contentLengthArr)
		fmt.Printf("size=%d\n", size)

		fmt.Printf("proceed? (y/n) ")
		input, err := stdinReader.ReadString('\n')
		if err != nil {
			fmt.Printf("err: %v\n", err)
			continue
		}

		if strings.ToLower(strings.TrimSpace(input)) != "y" {
			conn.Write([]byte{0})
			continue
		}

		if _, err := conn.Write([]byte{1}); err != nil {
			fmt.Printf("err: %v\n", err)
			continue
		}

		file, err := os.Create(string(filename))
		if err != nil {
			fmt.Printf("err: %v\n", err)
			continue
		}

		hash := sha256.New()
		tee := io.TeeReader(conn, hash)
		received := uint64(0)
		for received < size {
			block := BlockSize
			if size - received < BlockSize {
				block = size - received
			}
			n, err := io.CopyN(file, tee, int64(block))
			received += uint64(n)
			if err != nil {
				fmt.Printf("err after reading %d bytes: %v\n", received, err)
				break
			}
			fmt.Printf("%d / %d (%d%%)\n", received, size, 100*received/size)
		}

		fmt.Printf("Done receiving. SHA256: %x\n", hash.Sum(nil))
	}
}
