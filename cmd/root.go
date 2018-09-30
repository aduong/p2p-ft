package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/aduong/p2p-ft/common"
)

var logger *zap.SugaredLogger

var rootCmd = &cobra.Command{
	Use:   "p2p",
	Short: "p2p is an efficient and secure p2p file transfer utility",
}

func Execute() {
	logger = common.CreateLogger().Sugar()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
