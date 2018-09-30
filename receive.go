package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/grandcat/zeroconf"
)

func main() {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{})
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	defer listener.Close()
	localAddr := listener.Addr().(*net.TCPAddr)

	var serviceName string
	if len(os.Args) > 1 && os.Args[1] != "" {
		serviceName = os.Args[1]
	} else {
		id, _ := uuid.NewUUID()
		serviceName = id.String()
	}

	server, err := zeroconf.Register(serviceName, P2PServiceType, "local.", localAddr.Port, nil, nil)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	defer server.Shutdown()

	fmt.Printf("Service %s listening at %v\n", serviceName, localAddr)

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
			if _, err := io.Copy(conn, bytes.NewBuffer([]byte{0})); err != nil {
				fmt.Printf("err: %v\n", err)
			}
			continue
		}

		if _, err := io.Copy(conn, bytes.NewBuffer([]byte{1})); err != nil {
			fmt.Printf("err: %v\n", err)
			continue
		}

		fmt.Printf("decryption key: ")
		input, err = stdinReader.ReadString('\n')
		if err != nil {
			fmt.Printf("err: %v\n", err)
			continue
		}
		key, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			fmt.Printf("err: %v\n", err)
			continue
		}

		blockCipher, err := aes.NewCipher(key)
		if err != nil {
			fmt.Printf("err: %v\n", err)
			continue
		}

		iv := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(conn, iv); err != nil {
			fmt.Printf("err: %v\n", err)
			continue
		}

		streamCipher := cipher.NewCTR(blockCipher, iv)

		file, err := os.Create(string(filename))
		if err != nil {
			fmt.Printf("err: %v\n", err)
			continue
		}

		// initiate transfer
		if _, err := io.Copy(conn, bytes.NewBuffer([]byte{1})); err != nil {
			fmt.Printf("err: %v\n", err)
			continue
		}

		hash := sha256.New()
		tee := io.TeeReader(cipher.StreamReader{S: streamCipher, R: conn}, hash)
		received := uint64(0)
		startTime := time.Now()
		for received < size {
			block := BlockSize
			if size-received < BlockSize {
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
		endTime := time.Now()

		fmt.Printf("Done receiving. SHA256: %x\n", hash.Sum(nil))
		fmt.Printf("Received %d bytes in %d seconds\n", received, endTime.Unix()-startTime.Unix())
	}
}
