package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

func init() {
	convertCmd.PersistentFlags().StringVarP(&inputPath, "input", "i", "-", "input file path")
	convertCmd.PersistentFlags().StringVarP(&inputFormat, "from", "f", "", "input format")
	convertCmd.PersistentFlags().VarP(mapValue(inputArgs), "from-arg", "F", "input argument")
	convertCmd.PersistentFlags().StringVarP(&outputPath, "output", "o", "-", "output file path")
	convertCmd.PersistentFlags().StringVarP(&outputFormat, "to", "t", "", "output format")
	convertCmd.PersistentFlags().VarP(mapValue(outputArgs), "to-arg", "T", "output argument")
}

var convertCmd = &cobra.Command{
	Use:   "convert [OPTIONS]",
	Short: "Convert keys",
	//Long: "TODO",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		// Check arguments
		if len(args) > 0 {
			return fmt.Errorf("no arguments permitted")
		}
		if outputFormat == "" {
			return fmt.Errorf("must specify output format with --to")
		}
		// Read input
		var key interface{}
		if key, _, err = readInput(inputPath, inputFormat, inputArgs); err != nil {
			return
		}
		if _, err = writeOutput(outputPath, outputFormat, key, outputArgs); err != nil {
			return
		}
		return
	},
}
