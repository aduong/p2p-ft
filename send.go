package main

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
)

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s PEER FILE\n", os.Args[0])
		return
	}

	peer := os.Args[1]
	filepath := os.Args[2]

	file, err := os.Open(filepath)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}

	stat, err := file.Stat()
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	size := uint64(stat.Size())
	filename := stat.Name()
	if len(filename) > 256 {
		err := fmt.Errorf("filename %q too long", filename)
		fmt.Printf("err: %v\n", err)
		return
	}

	resolver, err := zeroconf.NewResolver()
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}

	entriesCh := make(chan *zeroconf.ServiceEntry)

	ctx, _ := context.WithTimeout(context.Background(), 2*time.Second)
	if err := resolver.Lookup(ctx, peer, P2PServiceType, "", entriesCh); err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}

	fmt.Printf("# resolving peer...\n")

	var service *zeroconf.ServiceEntry
	select {
	case <-ctx.Done():
		fmt.Printf("err: %v\n", ctx.Err())
		return
	case entry := <-entriesCh:
		service = entry
	}

	fmt.Printf("# resolved peer\n")

	if len(service.AddrIPv4) < 1 {
		err := fmt.Errorf("service has no IPv4 address")
		fmt.Printf("err: %v\n", err)
		return
	}

	addr := service.AddrIPv4[0]

	fmt.Printf("sending file %s (%d bytes) to peer %s at %v:%v\n", filepath, size, peer, addr, service.Port)

	// connect
	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: addr, Port: service.Port})
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	fmt.Printf("# connected\n")

	// send the filename
	filenameBytes := make([]byte, 256)
	copy(filenameBytes, []byte(filename))
	if _, err := io.Copy(conn, bytes.NewBuffer(filenameBytes)); err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	fmt.Printf("# sent filename\n")

	// send the length
	var sizeBytes [8]byte
	binary.BigEndian.PutUint64(sizeBytes[:], size)
	if _, err := io.Copy(conn, bytes.NewBuffer(sizeBytes[:])); err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	fmt.Printf("# sent length\n")

	fmt.Printf("waiting for acceptance...\n")

	// receive permission
	var yn [1]byte
	if _, err := io.ReadFull(conn, yn[:]); err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}

	if yn[0] != 1 {
		fmt.Printf("transfer denied\n")
		return
	}
	fmt.Printf("transfer accepted\n")

	// send IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	if _, err := io.Copy(conn, bytes.NewBuffer(iv)); err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	fmt.Printf("shared key is %s\n", base64.StdEncoding.EncodeToString(key))
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	streamCipher := cipher.NewCTR(blockCipher, iv)

	fmt.Printf("waiting for signal to start...\n")
	if _, err := io.ReadFull(conn, yn[:]); err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}

	// send data
	hash := sha256.New()
	tee := io.TeeReader(file, hash)
	sent := uint64(0)
	encryptedConn := cipher.StreamWriter{S: streamCipher, W: conn}
	startTime := time.Now()
	for sent < size {
		block := BlockSize
		if size-sent < BlockSize {
			block = size - sent
		}
		n, err := io.CopyN(encryptedConn, tee, int64(block))
		sent += uint64(n)
		if err != nil {
			fmt.Printf("err after sending %d bytes: %v\n", sent, err)
			return
		}
		fmt.Printf("%d / %d (%d%%)\n", sent, size, 100*sent/size)
	}
	endTime := time.Now()

	fmt.Printf("Done sending. SHA256: %x\n", hash.Sum(nil))
	fmt.Printf("Sent %d bytes in %d seconds\n", sent, endTime.Unix()-startTime.Unix())
}
