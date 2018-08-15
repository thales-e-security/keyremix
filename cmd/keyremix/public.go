package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"git.tesfabric.com/ignite/keyremix"
	"github.com/spf13/cobra"
)

func init() {
	publicCmd.PersistentFlags().StringVarP(&inputPath, "input", "i", "-", "input file path")
	publicCmd.PersistentFlags().StringVarP(&inputFormat, "from", "f", "", "input format")
	publicCmd.PersistentFlags().VarP(mapValue(inputArgs), "from-arg", "F", "input argument")
	publicCmd.PersistentFlags().StringVarP(&outputPath, "output", "o", "-", "output file path")
	publicCmd.PersistentFlags().StringVarP(&outputFormat, "to", "t", "", "output format")
	publicCmd.PersistentFlags().VarP(mapValue(outputArgs), "to-arg", "T", "output argument")
}

var publicCmd = &cobra.Command{
	Use:   "public [OPTIONS]",
	Short: "Extract public keys",
	//Long: "TODO",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		// Check arguments
		if len(args) > 0 {
			return fmt.Errorf("no arguments permitted")
		}
		// Read input
		var key interface{}
		var format keyremix.KeyFormat
		if key, format, err = readInput(inputPath, inputFormat, inputArgs); err != nil {
			return
		}
		// Convert to public key
		switch k := key.(type) {
		case *rsa.PrivateKey:
			key = k.Public()
		case *ecdsa.PrivateKey:
			key = k.Public()
		case *rsa.PublicKey, *ecdsa.PublicKey:
			// Nothing
		default:
			err = fmt.Errorf("%s: unrecognized key type %T", inputPath, key)
		}
		// Try to set a default output format based on the input
		// - DER inputs yield DER outputs
		// - In a PKCS#1 or JOSE world, stay there
		// - Otherwise choose PKIX
		if outputFormat == "" {
			inputFormat = format.Name()
			switch inputFormat {
			case "pkcs1", "pkcs1der":
				outputFormat = inputFormat
			case "jwk":
				outputFormat = "jwk"
			default:
				if len(inputFormat) >= 3 && inputFormat[len(inputFormat)-3:] == "der" {
					outputFormat = "pkixder"
				} else {
					outputFormat = "pkix"
				}
			}
		}
		// Save the output
		if _, err = writeOutput(outputPath, outputFormat, key, outputArgs); err != nil {
			return
		}
		return
	},
}
