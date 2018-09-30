package cmd

import (
	"bufio"
	"bytes"
	"context"
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
	"github.com/spf13/cobra"

	"github.com/aduong/p2p-ft/common"
	io2 "github.com/aduong/p2p-ft/io"
)

func init() {
	rootCmd.AddCommand(receiveCmd)
	//receiveCmd.Flags().StringVarP(&Source, "source", "s", "", "Source directory to read from")
}

var receiveCmd = &cobra.Command{
	Use:   "receive",
	Short: "Start receiving files from peers",
	RunE: func(cmd *cobra.Command, args []string) error {
		var serviceName string
		if len(args) > 0 {
			serviceName = args[0]
		}
		return receiver{serviceName}.receive()
	},
}

type receiver struct {
	serviceName string
}

func (r receiver) receive() error {
	serviceName := r.serviceName

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{})
	if err != nil {
		fmt.Printf("Couldn't start TCP listener: %v\n", err)
		return fmt.Errorf("listen tcp: %v", err)
	}
	defer listener.Close()
	localAddr := listener.Addr().(*net.TCPAddr)

	if serviceName == "" {
		id, _ := uuid.NewUUID()
		serviceName = id.String()
	}

	logger.Debugf("Registering service %s for type %s with zeroconf at port %d",
		serviceName, common.P2PServiceType, localAddr.Port)
	server, err := zeroconf.Register(serviceName, common.P2PServiceType, "local.", localAddr.Port, nil, nil)
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
		connHandler{conn, stdin}.handle()
		fmt.Println("Done handling request")
	}
}

type connHandler struct {
	conn  net.Conn
	stdin *bufio.Reader
}

func (h connHandler) handle() error {
	defer h.conn.Close()

	logger.Debug("reading file name...")
	filename, err := h.readFilename()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return err
	}
	fmt.Printf("File name: '%s'\n", filename)

	logger.Debug("reading file size")
	filesize, err := h.readContentLength()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return err
	}
	roughSize, sizeSuffix := common.PrettySize(filesize)
	fmt.Printf("File size: %s %s ~ %d bytes\n", roughSize, sizeSuffix, filesize)

	if proceed, err := h.readAndSendProceed(); err != nil {
		fmt.Printf("Error proceeding: %v\n", err)
		return err
	} else if !proceed {
		return nil
	}

	streamCipher, err := h.setupCrypto()
	if err != nil {
		fmt.Printf("Error setting up crypto: %v\n", err)
		return err
	}

	file, err := os.Create(string(filename))
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return err
	}

	logger.Debug("Initiating transfer with remote...")
	if _, err := io.Copy(h.conn, bytes.NewBuffer([]byte{1})); err != nil {
		fmt.Printf("Error initiating transfer: %v\n", err)
		return fmt.Errorf("send proceed: %v\n", err)
	}

	hash := sha256.New()
	tee := io.TeeReader(cipher.StreamReader{S: streamCipher, R: h.conn}, hash)
	startTime := time.Now()
	logger.Debugf("Awaiting bytes at %v. Block size is %d.", startTime, common.BlockSize)
	received, err := io2.CopyInChunks(context.TODO(), file, tee, filesize, common.BlockSize, func(received uint64) {
		fmt.Printf("%d / %d (%d%%) %d seconds elapsed\n",
			received, filesize, 100*received/filesize, time.Now().Unix()-startTime.Unix())
	})
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

func (h connHandler) readFilename() (string, error) {
	var filenameBytes [common.FilenameSize]byte
	if err := io2.ReadFull(h.conn, filenameBytes[:]); err != nil {
		return "", fmt.Errorf("read filename: %v", err)
	}
	filename := strings.TrimRight(string(filenameBytes[:]), "\x00")
	if !utf8.ValidString(filename) {
		logger.Debugf("Received invalid filename %q", filename)
		return "", fmt.Errorf("read filename: received name is not valid padded UTF-8")
	}
	return filename, nil
}

func (h connHandler) readContentLength() (uint64, error) {
	var contentLengthBytes [common.ContentLengthSize]byte
	if err := io2.ReadFull(h.conn, contentLengthBytes[:]); err != nil {
		return 0, fmt.Errorf("read content length: %v", err)
	}
	return binary.BigEndian.Uint64(contentLengthBytes[:]), nil
}

func (h connHandler) readAndSendProceed() (bool, error) {
	fmt.Print("Proceed? (y/n) ")
	input, err := h.stdin.ReadString('\n')
	if err != nil {
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
	_, err = io.Copy(h.conn, bytes.NewBuffer(response[:]))
	if err != nil {
		return false, fmt.Errorf("send proceed: %v", err)
	}
	return proceed, nil
}

func (h connHandler) setupCrypto() (cipher.Stream, error) {
	fmt.Print("Decryption key: ")
	input, err := h.stdin.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read decryption key: %v\n", err)
	}
	key, err := base64.RawStdEncoding.DecodeString(input)
	if err != nil {
		return nil, fmt.Errorf("read decryption key: %v\n", err)
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("setup crypto: %v\n", err)
	}

	return cipher.NewCTR(blockCipher, make([]byte, aes.BlockSize)), nil
}
