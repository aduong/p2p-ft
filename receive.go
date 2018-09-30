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
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/grandcat/zeroconf"
	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

func main() {
	exitCode := 0
	defer func() {
		if r := recover(); r != nil {
			panic(r)
		}
		os.Exit(exitCode)
	}()

	logger = createLogger().Sugar()
	defer logger.Sync()

	if err := execute(); err != nil {
		exitCode = 1
	}
}

func createLogger() *zap.Logger {
	cfg := zap.NewDevelopmentConfig()
	l, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	return l
}

func execute() error {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{})
	if err != nil {
		fmt.Printf("Couldn't start TCP listener: %v\n", err)
		return fmt.Errorf("listen tcp: %v", err)
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

	logger.Debugf("Registering service %s for type %s with zeroconf at port %d",
		serviceName, P2PServiceType, localAddr.Port)
	server, err := zeroconf.Register(serviceName, P2PServiceType, "local.", localAddr.Port, nil, nil)
	if err != nil {
		fmt.Printf("Couldn't register file transfer service: %v\n", err)
		return err
	}
	defer server.Shutdown()

	logger.Debugf("Registered service %s at %v", serviceName, localAddr)
	fmt.Printf("Ready to receive files as %s\n", serviceName)

	stdin := bufio.NewReader(os.Stdin)
	for {
		logger.Debugf("Waiting for connections")
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Couldn't wait for connections: %v\n", err)
			return fmt.Errorf("listen tcp: %v", err)
		}
		logger.Debugf("Accepted connection from %v", conn.RemoteAddr())
		fmt.Println("Incoming file")
		handleConn(conn, stdin)
		fmt.Println("Done handling request")
	}
}

func handleConn(conn net.Conn, stdin *bufio.Reader) error {
	defer conn.Close()

	logger.Debug("reading file name...")
	filename, err := readFilename(conn)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return err
	}
	fmt.Printf("File name: '%s'\n", filename)

	logger.Debug("reading file size")
	filesize, err := readContentLength(conn)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return err
	}
	roughSize, sizeSuffix := prettySize(filesize)
	fmt.Printf("File size: %s %s ~ %d bytes\n", roughSize, sizeSuffix, filesize)

	if proceed, err := readAndSendProceed(stdin, conn); err != nil {
		return err
	} else if !proceed {
		return nil
	}

	streamCipher, err := setupCrypto(stdin)
	if err != nil {
		return err
	}

	file, err := os.Create(string(filename))
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return err
	}

	logger.Debug("Initiating transfer with remote...")
	if _, err := io.Copy(conn, bytes.NewBuffer([]byte{1})); err != nil {
		fmt.Printf("Error initiating transfer: %v\n", err)
		return fmt.Errorf("send proceed: %v\n", err)
	}

	hash := sha256.New()
	tee := io.TeeReader(cipher.StreamReader{S: streamCipher, R: conn}, hash)
	startTime := time.Now()
	logger.Debugf("Awaiting bytes at %v. Block size is %d.", startTime, BlockSize)
	received, err := copyInChunks(file, tee, filesize, BlockSize)
	endTime := time.Now()
	if err != nil {
		logger.Debugf("Abrupt stop after %d bytes: %v", received, err)
		fmt.Printf("Error receiving file: %v\n", err)
		return fmt.Errorf("receive: %v", err)
	}

	fmt.Printf("Done receiving. SHA256: %x\n", hash.Sum(nil))
	fmt.Printf("Received %d bytes in %d seconds\n", received, endTime.Unix()-startTime.Unix())
	return nil
}

func readFilename(conn net.Conn) (string, error) {
	var filenameBytes [FilenameSize]byte
	if err := readFull(conn, filenameBytes[:]); err != nil {
		return "", fmt.Errorf("read filename: %v", err)
	}
	filename := strings.TrimRight(string(filenameBytes[:]), "\x00")
	if !utf8.ValidString(filename) {
		logger.Debugf("Received invalid filename %q", filename)
		return "", fmt.Errorf("read filename: received name is not valid padded UTF-8")
	}
	return filename, nil
}

func readContentLength(conn net.Conn) (uint64, error) {
	var contentLengthBytes [ContentLengthSize]byte
	if err := readFull(conn, contentLengthBytes[:]); err != nil {
		return 0, fmt.Errorf("read content length: %v", err)
	}
	return binary.BigEndian.Uint64(contentLengthBytes[:]), nil
}

func readFull(conn net.Conn, buf []byte) error {
	if n, err := io.ReadFull(conn, buf); err != nil {
		return err
	} else if n < len(buf) {
		return fmt.Errorf("received %d bytes but got %d", n, len(buf))
	}
	return nil
}

func readAndSendProceed(stdin *bufio.Reader, conn net.Conn) (bool, error) {
	fmt.Print("Proceed? (y/n) ")
	input, err := stdin.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading user input: %v\n", err)
		return false, fmt.Errorf("read proceed input: %v", err)
	}
	input = strings.TrimSpace(input)

	proceed := input == "y"

	var response [1]byte
	if proceed {
		response[0] = 1
	} else {
		response[0] = 0
	}
	logger.Debugf("Sending proceed (%v) to remote", response)
	_, err = io.Copy(conn, bytes.NewBuffer(response[:]))
	if err != nil {
		fmt.Printf("Error sending proceed to remote: %v\n", err)
		return false, fmt.Errorf("send proceed: %v", err)
	}
	return proceed, nil
}

func setupCrypto(stdin *bufio.Reader) (cipher.Stream, error) {
	fmt.Print("Decryption key: ")
	input, err := stdin.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading user input: %v\n", err)
		return nil, fmt.Errorf("read decryption key: %v\n", err)
	}
	key, err := base64.RawStdEncoding.DecodeString(input)
	if err != nil {
		fmt.Printf("Error decoding decryption key: %v\n", err)
		return nil, fmt.Errorf("read decryption key: %v\n", err)
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return nil, fmt.Errorf("setup crypto: %v\n", err)
	}

	return cipher.NewCTR(blockCipher, make([]byte, aes.BlockSize)), nil
}