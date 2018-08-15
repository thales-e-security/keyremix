package main

import (
	"github.com/spf13/cobra"
	"log"
	"os"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Printf("ERROR: %v", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(convertCmd)
	rootCmd.AddCommand(formatsCmd)
	rootCmd.AddCommand(publicCmd)
}

var rootCmd = cobra.Command{
	Use:   "keyremix SUBCOMMAND...",
	Short: "Convert keys between different formats",
	//Long: "TODO",
	SilenceErrors: true,
	SilenceUsage:  true,
}
