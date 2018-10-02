package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/grandcat/zeroconf"
	"github.com/spf13/cobra"

	"github.com/aduong/p2p-ft/common"
	io2 "github.com/aduong/p2p-ft/io"
)

var receiveDir string

func init() {
	rootCmd.AddCommand(receiveCmd)
	receiveCmd.Flags().StringVarP(
		&receiveDir, "receive-dir", "d", "received", "Directory to store received files")
}

var receiveCmd = &cobra.Command{
	Use:   "receive [NAME]",
	Short: "Start receiving files from peers",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var serviceName string
		if len(args) > 0 {
			serviceName = args[0]
		}
		r := receiver{serviceName}
		if err := r.receive(); err != nil {
			os.Exit(1)
		}
	},
}

type receiver struct {
	serviceName string
}

func (r receiver) receive() error {
	if err := os.MkdirAll(receiveDir, 0700); err != nil {
		fmt.Printf("Couldn't create receive directory: %v\n", err)
		return fmt.Errorf("create receive dir: %v", err)
	}

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
	filesize, err := io2.ReadUInt64(h.conn)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return err
	}
	roughSize, sizeSuffix := common.PrettySize(filesize)
	fmt.Printf("File size: %d B ~ %s %s \n", filesize, roughSize, sizeSuffix)

	logger.Debug("Waiting for hash from remote...")
	hash := [sha256.Size]byte{}
	if _, err := io.ReadFull(h.conn, hash[:]); err != nil {
		fmt.Printf("Error receiving file hash: %v\n", err)
		return err
	}
	logger.Debugf("Received file hash is %x", hash)

	prevSize := uint64(0)

	if existingHash, err := h.hashOfExistingFile(filename); err != nil {
		return err
	} else if common.EqualBytes(hash[:], existingHash) {
		logger.Debugf("Already have the file with name %s and hash %x", filename, hash)
		fmt.Println("That file has already been received!")
		prevSize = filesize
	}

	if prevSize == 0 {
		prevSize, err = h.existingHashFile(hash[:])
		if err != nil {
			fmt.Printf("Error checking for existing hash file: %v\n", err)
			return err
		}
		logger.Debugf("Size from file with name %x: %d", hash, prevSize)
	}

	logger.Debugf("Sending size %d to peer", prevSize)
	if err := io2.WriteUInt64(h.conn, prevSize); err != nil {
		fmt.Printf("Error sending previously received file size back: %v\n", err)
		return err
	}

	if prevSize == filesize {
		return h.sendProceed(false)
	}

	proceed, err := h.readProceed()
	if err != nil {
		fmt.Printf("Error proceeding: %v\n", err)
		return err
	}
	if !proceed {
		return h.sendProceed(false)
	}
	if err := h.sendProceed(true); err != nil {
		fmt.Printf("Error signalling to proceed: %v\n", err)
		return err
	}

	streamCipher, err := h.setupCrypto()
	if err != nil {
		fmt.Printf("Error setting up crypto: %v\n", err)
		return err
	}

	file, err := os.OpenFile(path.Join(receiveDir, hex.EncodeToString(hash[:])), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return err
	}

	logger.Debug("Initiating transfer with remote...")
	if _, err := io.Copy(h.conn, bytes.NewReader([]byte{1})); err != nil {
		fmt.Printf("Error initiating transfer: %v\n", err)
		return fmt.Errorf("send proceed: %v\n", err)
	}

	startTime := time.Now()
	logger.Debugf("Awaiting bytes at %v. Block size is %d.", startTime, common.BlockSize)
	toReceive := filesize - prevSize
	received, err := io2.CopyInChunks(context.TODO(), file, cipher.StreamReader{S: streamCipher, R: h.conn}, toReceive, common.BlockSize, func(received uint64) {
		fmt.Printf("%d / %d (%d%%) %d seconds elapsed\n",
			received, filesize, 100*received/toReceive, time.Now().Unix()-startTime.Unix())
	})
	endTime := time.Now()
	if err != nil {
		logger.Debugf("Abrupt stop after %d bytes: %v", received, err)
		fmt.Printf("Error receiving file: %v\n", err)
		return fmt.Errorf("receive: %v", err)
	}

	fmt.Println("Done receiving.")
	fmt.Printf("Received %d bytes in %d seconds\n", received, endTime.Unix()-startTime.Unix())

	if err := os.Rename(
		path.Join(receiveDir, hex.EncodeToString(hash[:])),
		path.Join(receiveDir, filename)); err != nil {
		fmt.Printf("Error moving completed file: %v\n", err)
	}

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

func (h connHandler) readProceed() (bool, error) {
	fmt.Print("Proceed? (y/n) ")
	input, err := h.stdin.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("read proceed input: %v", err)
	}
	input = strings.TrimSpace(input)

	proceed := input == "y"

	return proceed, nil
}

func (h connHandler) sendProceed(proceed bool) error {
	response := [1]byte{}
	if proceed {
		response[0] = 1
	} else {
		response[0] = 0
	}
	logger.Debugf("Sending proceed (%v) to remote", response)

	if _, err := io.Copy(h.conn, bytes.NewReader(response[:])); err != nil {
		return fmt.Errorf("send proceed: %v", err)
	}
	return nil
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

func (h connHandler) hashOfExistingFile(filename string) ([]byte, error) {
	file, err := os.Open(path.Join(receiveDir, filename))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("hash file: %v", err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, fmt.Errorf("hash file: %v", err)
	}
	return hash.Sum(nil), nil
}

func (h connHandler) existingHashFile(hash []byte) (uint64, error) {
	info, err := os.Stat(path.Join(receiveDir, hex.EncodeToString(hash)))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return uint64(info.Size()), nil
}
