package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/aduong/p2p-ft/common"
)

var logger *zap.SugaredLogger
var debug bool

func init() {
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "")
}

var rootCmd = &cobra.Command{
	Use:   "p2p",
	Short: "p2p is an efficient and secure p2p file transfer utility",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logger = common.CreateLogger(debug).Sugar()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
