package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "aegis-proxy",
	Short: "aegis-proxy, the proxy server for aegis",
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().CountP("verbose", "v", "Set the verbosity level")
	rootCmd.AddCommand(runCmd)
}

func initConfig() {
	// Get the verbosity level
	verbosity, err := rootCmd.PersistentFlags().GetCount("verbose")
	if err != nil || verbosity == 0 {
		verbosity = 0
	}

	// setting zerolog level
	var zlogLevel zerolog.Level
	switch verbosity {
	case 1:
		zlogLevel = zerolog.ErrorLevel
	case 2:
		zlogLevel = zerolog.WarnLevel
	case 3:
		zlogLevel = zerolog.InfoLevel
	case 4:
		zlogLevel = zerolog.DebugLevel
	case 5:
		zlogLevel = zerolog.TraceLevel
	default:
		zlogLevel = zerolog.Disabled
	}

	zerolog.SetGlobalLevel(zlogLevel)

	zerolog.TimeFieldFormat = "2006-01-02T15:04:05.999Z07:00"
	output := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "2006-01-02T15:04:05.999Z07:00"}
	output.FormatFieldName = func(i interface{}) string {
		return fmt.Sprintf("%s:", i)
	}
	log.Logger = zerolog.New(output).With().Timestamp().Logger()
}
