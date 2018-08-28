package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/thales-e-security/keyremix"
	"sort"
)

var formatsCmd = &cobra.Command{
	Use:   "formats",
	Short: "List formats",
	//Long: "TODO",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		// Check arguments
		if len(args) > 0 {
			return fmt.Errorf("no arguments permitted")
		}
		maxLength := 0
		var names []string
		for name := range keyremix.KeyFormats {
			names = append(names, name)
			if len(name) > maxLength {
				maxLength = len(name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			description := keyremix.KeyFormats[name].Description()
			if _, err = fmt.Printf("%-*s  %s\n", maxLength, name, description); err != nil {
				return
			}
		}
		return
	},
}
