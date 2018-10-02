# An efficient and secure LAN P2P file transfer utility

## Installing

    go get github.com/aduong/p2p-ft

## Using

On the receiving side

    p2p receive adrian

On the sending side

    p2p send adrian ~/archive.tar.gz

## Demo

TODO

## Features

* mDNS/DNS-SD discoverability: discover peers on the network who are ready to receive files
* AES256 encryption with ephemeral keys: so nobody is snooping
* Resume transfers in case the connection breaks or to transfer over multiple sessions
