package cmd

import (
	"fmt"
	"os"

	"github.com/numary/go-libs/sharedlogging"
	"github.com/numary/go-libs/sharedlogging/sharedlogginglogrus"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	Version   = "develop"
	BuildDate = "-"
	Commit    = "-"
)

const (
	debugFlag = "debug"
)

func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use: "auth",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {

			if err := bindFlagsToViper(cmd); err != nil {
				return err
			}

			logrusLogger := logrus.New()
			if viper.GetBool(debugFlag) {
				logrusLogger.SetLevel(logrus.DebugLevel)
				logrusLogger.Infof("Debug mode enabled.")
			}
			logger := sharedlogginglogrus.New(logrusLogger)
			sharedlogging.SetFactory(sharedlogging.StaticLoggerFactory(logger))

			return nil
		},
	}

	root.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	root.PersistentFlags().BoolP(debugFlag, "d", false, "Debug mode")

	root.AddCommand(serveCmd)
	root.AddCommand(versionCmd)

	return root
}

func exitWithCode(code int, v ...any) {
	fmt.Fprintln(os.Stdout, v...)
	os.Exit(code)
}

func Execute() {
	if err := NewRootCommand().Execute(); err != nil {
		exitWithCode(1, err)
	}
}
