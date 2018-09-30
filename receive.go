package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"github.com/google/uuid"
	"github.com/grandcat/zeroconf"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"bytes"
	"crypto/sha256"
	"time"
	"strings"
	"encoding/binary"
	"encoding/base64"
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

	stdin := bufio.NewReader(os.Stdin)
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("err: %v\n", err)
			break
		}
		fmt.Printf("# accepted connection\n")
		handleConn(conn, stdin)
	}
}

func handleConn(conn net.Conn, stdin *bufio.Reader) error {
	defer conn.Close()

	filenameBytes := make([]byte, 256)
	contentLengthBytes := make([]byte, 8)

	if n, err := io.ReadFull(conn, filenameBytes); err != nil {
		fmt.Printf("err: %v\n", err)
		return err
	} else if n < len(filenameBytes) {
		err := fmt.Errorf("expected %d bytes", len(filenameBytes))
		fmt.Printf("err: %v\n", err)
		return err
	}
	filename := strings.TrimRight(string(filenameBytes), "\x00")
	fmt.Printf("filename=%s\n", filename)

	if n, err := io.ReadFull(conn, contentLengthBytes); err != nil {
		fmt.Printf("err: %v\n", err)
		return err
	} else if n < len(contentLengthBytes) {
		err := fmt.Errorf("expected %d bytes", len(contentLengthBytes))
		fmt.Printf("err: %v\n", err)
		return err
	}
	size := binary.BigEndian.Uint64(contentLengthBytes)
	fmt.Printf("size=%d\n", size)

	fmt.Printf("proceed? (y/n) ")
	input, err := stdin.ReadString('\n')
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return err
	}

	if strings.ToLower(strings.TrimSpace(input)) != "y" {
		if _, err := io.Copy(conn, bytes.NewBuffer([]byte{0})); err != nil {
			fmt.Printf("err: %v\n", err)
		}
		return err
	}

	if _, err := io.Copy(conn, bytes.NewBuffer([]byte{1})); err != nil {
		fmt.Printf("err: %v\n", err)
		return err
	}

	fmt.Printf("decryption key: ")
	input, err = stdin.ReadString('\n')
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return err
	}
	key, err := base64.RawStdEncoding.DecodeString(input)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return err
	}

	streamCipher := cipher.NewCTR(blockCipher, make([]byte, aes.BlockSize))

	file, err := os.Create(string(filename))
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return err
	}

	// initiate transfer
	if _, err := io.Copy(conn, bytes.NewBuffer([]byte{1})); err != nil {
		fmt.Printf("err: %v\n", err)
		return err
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
	return nil
}