package keyremix

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"
)

type text struct {
}

type value struct {
	name  string
	value interface{}
}

func (p *text) Serialize(key interface{}, args map[string]string) (output []byte, err error) {
	if _, ok := args["password"]; ok {
		err = ErrNotImplemented
		return
	}
	f := &bytes.Buffer{}

	var ok bool
	var base string
	if base, ok = args["base"]; !ok {
		base = "hex"
	}
	format := "%x"
	switch strings.ToLower(base) {
	case "dec", "10":
		format = "%d"
	case "oct", "8":
		format = "%#o"
	case "hex", "16":
		format = "%#x"
	default:
		err = fmt.Errorf("unknown base indicator")
		return
	}
	values := make([]value, 0, 16)

	switch k := key.(type) {
	case *rsa.PrivateKey:
		values = append(values, value{"n", k.N})
		values = append(values, value{"e", k.E})
		values = append(values, value{"d", k.D})
		values = append(values, value{"p", k.Primes[0]})
		values = append(values, value{"q", k.Primes[1]})
		values = append(values, value{"dmp1", k.Precomputed.Dp})
		values = append(values, value{"dmq1", k.Precomputed.Dq})
		values = append(values, value{"iqmp", k.Precomputed.Qinv})
	case *rsa.PublicKey:
		values = append(values, value{"n", k.N})
		values = append(values, value{"e", k.E})
	case *ecdsa.PrivateKey:
		values = append(values, value{"curve", k.Params().Name})
		values = append(values, value{"x", k.X})
		values = append(values, value{"y", k.Y})
		values = append(values, value{"d", k.D})
	case *ecdsa.PublicKey:
		values = append(values, value{"curve", k.Params().Name})
		values = append(values, value{"x", k.X})
		values = append(values, value{"y", k.Y})
	default:
		err = ErrUnsuitableKeyType
		return
	}
	for _, value := range values {
		if _, err = fmt.Fprintf(f, "%s: ", value.name); err != nil {
			return
		}
		switch v := value.value.(type) {
		case string:
			if _, err = fmt.Fprintf(f, "%s", v); err != nil {
				return
			}
		case *big.Int:
			if _, err = fmt.Fprintf(f, format, v); err != nil {
				return
			}
		case int:
			if _, err = fmt.Fprintf(f, format, v); err != nil {
				return
			}
		default:
			panic(fmt.Sprintf("unrecognized value type: %T", value.value))
		}
		if _, err = fmt.Fprintf(f, "\n"); err != nil {
			return
		}

	}
	output = f.Bytes()
	return
}

func (p *text) Deserialize(input []byte, args map[string]string) (key interface{}, rest []byte, err error) {
	err = ErrUnsuitableKeyType
	return
}

func (p *text) Recognize(input []byte, args map[string]string) (fit Fit, err error) {
	fit = DoesNotFit
	return
}

func (p *text) Name() string {
	return "text"
}

func (p *text) Description() string {
	return "human-readable key representation (output only)"
}

// Text is a human-readable key representation.
//
// Only RSA and ECDSA private keys are supported.
var Text = &text{}

func init() {
	registerKeyFormat(Text)
}
