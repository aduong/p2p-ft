package cmd

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/spf13/cobra"

	"github.com/aduong/p2p-ft/common"
	io2 "github.com/aduong/p2p-ft/io"
	"github.com/aduong/p2p-ft/proto"
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
	Run: func(cmd *cobra.Command, args []string) {
		if err := send(args[0], args[1]); err != nil {
			os.Exit(1)
		}
	},
}

func send(peer, filepath string) error {
	// checking file
	file, filename, filesize, err := openFile(filepath)
	defer file.Close()

	if err != nil {
		fmt.Printf("Error opening/checking file: %v\n", err)
		return err
	}

	// resolving peer
	fmt.Printf("Resolving peer '%s'...\n", peer)
	addr, err := resolvePeer(peer)
	if err != nil {
		fmt.Printf("Error resolving peer: %v\n", err)
		return err
	}

	fmt.Printf("Send file %s (%d bytes) to peer %s at %v\n", filepath, filesize, peer, addr)

	// connect
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return err
	}
	logger.Debugf("Connected to %v", addr)

	fmt.Println("Hashing file...")
	h, err := hash(file)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return err
	}

	req := proto.RequestToSend{
		Filename:      filename,
		ContentLength: filesize,
		SHA256sum:     h,
	}

	logger.Debugf("Sending request to send: %+v...", req)
	if err := req.Send(conn); err != nil {
		fmt.Printf("Error: failed to send request: %v\n", err)
		return err
	}

	logger.Debugf("Waiting for request to receive...")
	res := proto.RequestToReceive{}
	if err := res.Read(conn); err != nil {
		fmt.Printf("Error: failed to receive response: %v\n", err)
		return err
	}
	logger.Debugf("Request to receive received: %+v", res)

	if !res.Proceed {
		if res.Offset == filesize {
			fmt.Println("File already sent")
			return nil
		}
		fmt.Println("Transfer denied")
		return fmt.Errorf("transfer denied")
	}
	fmt.Println("Transfer accepted")

	if _, err := file.Seek(int64(res.Offset), 0); err != nil {
		fmt.Printf("Error: %v\n", err)
		return err
	}

	streamCipher, key, err := createStream()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return err
	}
	fmt.Printf("Shared key is %s\n", key)

	fmt.Println("Waiting for remote to start transfer...")
	if _, err := io.ReadFull(conn, []byte{0}); err != nil {
		fmt.Printf("Error waiting for remote to start transfer: %v\n", err)
		return err
	}

	// send data
	encryptedConn := cipher.StreamWriter{S: streamCipher, W: conn}
	startTime := time.Now()
	logger.Debugf("Transferring bytes starting at %v. Offset: %d. Block size is %d.",
		startTime, res.Offset, common.BlockSize)
	toSend := filesize - res.Offset
	sent, err := io2.CopyInChunks(context.TODO(), encryptedConn, file, toSend, common.BlockSize, func(sent uint64) {
		fmt.Printf("%d / %d (%d%%) %d seconds elapsed\n",
			sent, filesize, 100*sent/toSend, time.Now().Unix()-startTime.Unix())
	})
	endTime := time.Now()
	if err != nil {
		fmt.Printf("Error sending file: %v\n", err)
		return fmt.Errorf("send: %v", err)
	}

	fmt.Println("Done sending.")
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

func hash(file *os.File) ([sha256.Size]byte, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("hash file: %v", err)
	}
	var h [sha256.Size]byte
	copy(h[:], hash.Sum(nil))
	return h, nil
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
