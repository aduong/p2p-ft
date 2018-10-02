package cmd

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/grandcat/zeroconf"
	"github.com/spf13/cobra"

	"github.com/aduong/p2p-ft/common"
)

func init() {
	rootCmd.AddCommand(peersCmd)
}

var peersCmd = &cobra.Command{
	Use:   "peers",
	Short: "List peers that can receive files",
	Run: func(cmd *cobra.Command, args []string) {
		if err := listPeers(); err != nil {
			os.Exit(1)
		}
	},
}

func listPeers() error {
	resolver, err := zeroconf.NewResolver()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return err
	}

	entriesCh := make(chan *zeroconf.ServiceEntry)

	if err := resolver.Browse(context.Background(), common.P2PServiceType, "", entriesCh); err != nil {
		fmt.Printf("Error: %v\n", err)
		return err
	}

	for entry := range entriesCh {
		var addr net.IP
		if len(entry.AddrIPv4) > 0 {
			addr = entry.AddrIPv4[0]
		}
		fmt.Printf("%s at %s %s:%d\n", entry.Instance, entry.HostName, addr, entry.Port)
	}
	return nil
}
