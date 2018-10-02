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
	"github.com/aduong/p2p-ft/proto"
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

	logger.Debugf("Waiting for request to send...")
	req := proto.RequestToSend{}
	if err := req.Read(h.conn); err != nil {
		fmt.Printf("Error: %v\n", err)
		return err
	}
	logger.Debugf("Received request: %+v", req)

	printReq(req)

	prevSize := uint64(0)

	if existingHash, err := h.hashOfExistingFile(req.Filename); err != nil {
		fmt.Printf("Error: %v\n", err)
		return err
	} else if common.EqualBytes(req.SHA256sum[:], existingHash) {
		logger.Debugf("Already have the file with name %s and hash %x", req.Filename, hash)
		prevSize = req.ContentLength
	}

	incompleteFilename := hex.EncodeToString(req.SHA256sum[:])

	if prevSize == 0 {
		var err error
		prevSize, err = filesize(incompleteFilename)
		if err != nil {
			fmt.Printf("Error checking for existing hash file: %v\n", err)
			return err
		}
		if prevSize > 0 {
			remain := req.ContentLength - prevSize
			s, suf := common.PrettySize(remain)
			fmt.Printf("File with hash %x previously received but stopped at %d bytes.\n%d bytes ~ %s %s remain\n",
				req.SHA256sum, prevSize, remain, s, suf)
		}
		logger.Debugf("Size from file with name %s: %d", incompleteFilename, prevSize)
	}

	if prevSize == req.ContentLength {
		fmt.Println("That file has already been received!")
		res := proto.RequestToReceive{
			Offset:  req.ContentLength,
			Proceed: false,
		}
		return res.Send(h.conn)
	}

	proceed, err := h.readProceed()
	if err != nil {
		fmt.Printf("Error proceeding: %v\n", err)
		return err
	}

	res := proto.RequestToReceive{
		Offset:  prevSize,
		Proceed: proceed,
	}
	if !proceed {
		return res.Send(h.conn)
	}
	if err := res.Send(h.conn); err != nil {
		fmt.Printf("Error: %v\n", err)
		return err
	}

	streamCipher, err := h.setupCrypto()
	if err != nil {
		fmt.Printf("Error setting up crypto: %v\n", err)
		return err
	}

	file, err := os.OpenFile(
		path.Join(receiveDir, incompleteFilename),
		os.O_WRONLY|os.O_APPEND|os.O_CREATE,
		0666)
	defer file.Close()
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
	toReceive := req.ContentLength - prevSize
	received, err := io2.CopyInChunks(context.TODO(), file, cipher.StreamReader{S: streamCipher, R: h.conn}, toReceive, common.BlockSize, func(received uint64) {
		fmt.Printf("%d / %d (%d%%) %d seconds elapsed\n",
			received, req.ContentLength, 100*received/toReceive, time.Now().Unix()-startTime.Unix())
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
		path.Join(receiveDir, incompleteFilename),
		path.Join(receiveDir, req.Filename)); err != nil {
		fmt.Printf("Error moving completed file: %v\n", err)
	}

	return nil
}

func (h connHandler) readFilename() (string, error) {
	var filenameBytes [proto.FilenameSize]byte
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

func filesize(filename string) (uint64, error) {
	info, err := os.Stat(path.Join(receiveDir, filename))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return uint64(info.Size()), nil
}

func printReq(req proto.RequestToSend) {
	fmt.Printf("Filename: %s\n", req.Filename)
	s, suf := common.PrettySize(req.ContentLength)
	fmt.Printf("Size: %d B ~ %s %s\n", req.ContentLength, s, suf)
	fmt.Printf("SHA256 hash: %x\n", req.SHA256sum)
}
