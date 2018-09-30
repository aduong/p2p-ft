package cmd

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/spf13/cobra"

	"github.com/aduong/p2p-ft/common"
	io2 "github.com/aduong/p2p-ft/io"
)

func init() {
	rootCmd.AddCommand(sendCmd)
}

var sendCmd = &cobra.Command{
	Use:   "send PEER FILE",
	Short: "Send a file to a peer",
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(2)(cmd, args); err != nil {
			return err
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("not enough arguments")
		}
		return send(args[0], args[1])
	},
}

func send(peer, filepath string) error {
	// checking file
	file, filename, size, err := openFile(filepath)
	if err != nil {
		fmt.Printf("Error opening/checking file: %v\n", err)
		return err
	}

	// resolving peer
	fmt.Printf("Resolving peer '%s'...", peer)
	addr, err := resolvePeer(peer)
	if err != nil {
		fmt.Printf("Error resolving peer: %v\n", err)
		return err
	}

	fmt.Printf("Send file %s (%d bytes) to peer %s at %v\n", filepath, size, peer, addr)

	// connect
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return err
	}
	fmt.Printf("# connected\n")

	// send the filename
	var filenameBytes [common.FilenameSize]byte
	copy(filenameBytes[:], []byte(filename)) // just in case
	if _, err := io.Copy(conn, bytes.NewBuffer(filenameBytes[:])); err != nil {
		fmt.Printf("Error sending file name: %v\n", err)
		return err
	}
	fmt.Printf("# sent filename\n")

	// send the size
	var sizeBytes [8]byte
	binary.BigEndian.PutUint64(sizeBytes[:], size)
	if _, err := io.Copy(conn, bytes.NewBuffer(sizeBytes[:])); err != nil {
		fmt.Printf("Error sending file size: %v\n", err)
		return err
	}
	fmt.Printf("# sent length\n")

	fmt.Printf("waiting for acceptance...\n")

	// receive permission
	var yn [1]byte
	if err := io2.ReadFull(conn, yn[:]); err != nil {
		fmt.Printf("Error reading peer's response to proceed: %v\n", err)
		return fmt.Errorf("read proceed: %v", err)
	}

	if yn[0] != 1 {
		fmt.Printf("transfer denied\n")
		return fmt.Errorf("transfer denied")
	}
	fmt.Printf("transfer accepted\n")

	streamCipher, key, err := createStream()
	if err != nil {
		fmt.Printf("Error setting up crypto: %v", err)
		return err
	}
	fmt.Printf("Shared key is %s\n", key)

	fmt.Printf("Waiting for remote to start transfer...\n")
	if _, err := io.ReadFull(conn, yn[:]); err != nil {
		fmt.Printf("err: %v\n", err)
		return err
	}

	// send data
	hash := sha256.New()
	tee := io.TeeReader(file, hash)
	encryptedConn := cipher.StreamWriter{S: streamCipher, W: conn}
	startTime := time.Now()
	logger.Debugf("Transferring bytes starting at %v. Block size is %d.", startTime, common.BlockSize)
	sent, err := io2.CopyInChunks(context.TODO(), encryptedConn, tee, size, common.BlockSize, func(sent uint64) {
		fmt.Printf("%d / %d (%d%%) %d seconds elapsed\n",
			sent, size, 100*sent/size, time.Now().Unix()-startTime.Unix())
	})
	endTime := time.Now()
	if err != nil {
		fmt.Printf("Error sending file: %v\n", err)
		return fmt.Errorf("send: %v", err)
	}

	fmt.Printf("Done sending. SHA256: %x\n", hash.Sum(nil))
	fmt.Printf("Sent %d bytes in %d seconds\n", sent, endTime.Unix()-startTime.Unix())
	return nil
}

func openFile(path string) (*os.File, string, uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "", 0, fmt.Errorf("check file: %v", err)
	}

	stat, err := file.Stat()
	if err != nil {
		return nil, "", 0, fmt.Errorf("check file: %v", err)
	}
	filename := stat.Name()
	if len(filename) > 256 {
		return nil, "", 0, fmt.Errorf("check file: filename %q too long", filename)
	}
	return file, filename, uint64(stat.Size()), nil
}

func resolvePeer(peer string) (*net.TCPAddr, error) {
	errf := func(err error) error {
		return fmt.Errorf("resolve peer: %v", err)
	}

	resolver, err := zeroconf.NewResolver()
	if err != nil {
		return nil, errf(err)
	}

	entriesCh := make(chan *zeroconf.ServiceEntry)

	timeout := 2 * time.Second
	logger.Debugf("Looking up service %s of type %s with timeout %v", peer, common.P2PServiceType, timeout)

	ctx, _ := context.WithTimeout(context.Background(), timeout)
	if err := resolver.Lookup(ctx, peer, common.P2PServiceType, "", entriesCh); err != nil {
		return nil, errf(err)
	}

	var service *zeroconf.ServiceEntry
	select {
	case <-ctx.Done():
		err := ctx.Err()
		logger.Debugf("Timeout: %v", err)
		return nil, errf(err)
	case entry := <-entriesCh:
		logger.Debugf("Received a service entry: %v", entry)
		service = entry
	}

	if len(service.AddrIPv4) < 1 {
		return nil, errf(fmt.Errorf("service has no IPv4 address"))
	}

	addr := service.AddrIPv4[0]

	return &net.TCPAddr{IP: addr, Port: service.Port}, nil
}

func createStream() (cipher.Stream, string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, "", fmt.Errorf("setup crypto: %v", err)
	}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, "", fmt.Errorf("setup crypto: %v", err)
	}
	return cipher.NewCTR(blockCipher, make([]byte, aes.BlockSize)),
		base64.RawStdEncoding.EncodeToString(key),
		nil
}
