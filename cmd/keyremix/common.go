package main

import (
	"bytes"
	"fmt"
	"github.com/thales-e-security/keyremix"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
	"syscall"
)

var inputPath, inputFormat string
var outputPath, outputFormat string
var inputArgs = map[string]string{}
var outputArgs = map[string]string{}

// readInput reads a key from some and converts it to internal form.
// It returns the key and the format used.
func readInput(inputPath string, inputFormat string, inargs map[string]string) (key interface{}, format keyremix.KeyFormat, err error) {
	// Read input
	var input []byte
	if inputPath == "-" {
		if input, err = ioutil.ReadAll(os.Stdin); err != nil {
			return
		}
	} else {
		if input, err = ioutil.ReadFile(inputPath); err != nil {
			return
		}
	}
	// Determine input format
	if inputFormat == "" {
		// None specified, try to guess
		var ambiguouskfs []keyremix.KeyFormat
		for _, kf := range keyremix.KeyFormats {
			var fit keyremix.Fit
			fit, err = kf.Recognize(input, inargs)
			switch fit {
			case keyremix.AmbiguousFit:
				ambiguouskfs = append(ambiguouskfs, kf)
			case keyremix.UnambiguousFit:
				format = kf
			}
		}
		if format == nil {
			switch len(ambiguouskfs) {
			case 0:
				err = fmt.Errorf("%s: not a known key format", inputPath)
				return
			case 1:
				format = ambiguouskfs[0]
			default:
				err = fmt.Errorf("%s: could not unambiguously determine key format", inputPath)
				return
			}
		}
	} else {
		// User specified a specific key format
		var ok bool
		if format, ok = keyremix.KeyFormats[inputFormat]; !ok {
			err = fmt.Errorf("%s: unknown key format", inputFormat)
			return
		}
	}
	// Attempt to parse the input
	if key, _, err = format.Deserialize(input, inargs); err == keyremix.ErrPasswordRequired {
		var password []byte
		if _, err = fmt.Printf("Enter decryption password: "); err != nil {
			return
		}
		if password, err = terminal.ReadPassword(int(syscall.Stdin)); err != nil {
			return
		}
		inargs["password"] = string(password)
		key, _, err = format.Deserialize(input, inargs)
	}
	if err != nil {
		err = fmt.Errorf("deserializing key as %s: %s", format.Name(), err)
		return
	}
	return
}

// writeOutput writes the output. It returns the format selected.
func writeOutput(outputPath string, outputFormat string, key interface{}, outargs map[string]string) (format keyremix.KeyFormat, err error) {
	// Determine output key format
	var ok bool
	if format, ok = keyremix.KeyFormats[outputFormat]; !ok {
		err = fmt.Errorf("%s: unknown key format", outputFormat)
		return
	}
	// TODO should be an option to do private->public derivation (also public->private l-)
	// Convert to the output format
	var output []byte
	if output, err = format.Serialize(key, outargs); err == keyremix.ErrPasswordRequired {
		var password, check []byte
		for {
			if _, err = fmt.Printf("Enter encryption password: "); err != nil {
				return
			}
			if password, err = terminal.ReadPassword(int(syscall.Stdin)); err != nil {
				return
			}
			if _, err = fmt.Printf("\nConfirm encryption password: "); err != nil {
				return
			}
			if check, err = terminal.ReadPassword(int(syscall.Stdin)); err != nil {
				return
			}
			if _, err = fmt.Printf("\n"); err != nil {
				return
			}
			if bytes.Compare(password, check) == 0 {
				break
			}
			if _, err = fmt.Printf("Password do not match, try again\n"); err != nil {
				return
			}
		}
		outargs["password"] = string(password)
		output, err = format.Serialize(key, outargs)
	}

	if err != nil {
		err = fmt.Errorf("serializing key as %s: %s", format.Name(), err)
		return
	}
	// Write the output
	if outputPath == "-" {
		if _, err = os.Stdout.Write(output); err != nil {
			return
		}
	} else {
		if err = ioutil.WriteFile(outputPath, output, 0666); err != nil {
			return
		}
	}
	return
}
