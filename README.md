# An efficient and secure LAN P2P file transfer utility

## Features

* mDNS/DNS-SD discoverability: discover peers on the network who are ready to receive files
* AES256 encryption with ephemeral keys: so nobody snooping can see the file
* Resume transfers in case the connection breaks or to transfer over multiple sessions

## Installing

    go get github.com/aduong/p2p-ft

## Using

On the receiving side

    p2p-ft receive adrian

On the sending side

    p2p-ft send adrian ~/archive.tar.gz

## Demo

Receiver

[![asciicast](https://asciinema.org/a/d2b4qHdVEtZ6BIOygKTRFIzdC.png)](https://asciinema.org/a/d2b4qHdVEtZ6BIOygKTRFIzdC)

Sender

[![asciicast](https://asciinema.org/a/NI1XWS8UExQU65i3f9euKlI4t.png)](https://asciinema.org/a/NI1XWS8UExQU65i3f9euKlI4t)

## Security

A 256-bit key is created per file _transfer_ for use with AES in CTR mode (fixed IV). This key is meant to be transmitted via some other secure channel to the receiver. All other information including the file name, file size, and SHA256 hash of the file are transmitted in plain text. This means that the integrity of the file is not guaranteed. The SHA256 hash should be transmitted via a separate secure channel as well.
