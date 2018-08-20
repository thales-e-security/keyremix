package keyremix

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
)

type text struct {
}

func (p *text) Serialize(key interface{}, args map[string]string) (output []byte, err error) {
	f := &bytes.Buffer{}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		if _, err = fmt.Fprintf(f, "n: %#x\ne: %#x\nd: %#x\np: %#x\nq: %#x\ndmp1: %#x\ndmq1: %#x\niqmp: %#x\n",
			k.N, k.E,
			k.D,
			k.Primes[0], k.Primes[1],
			k.Precomputed.Dp, k.Precomputed.Dq, k.Precomputed.Qinv); err != nil {
			return
		}
	case *rsa.PublicKey:
		if _, err = fmt.Fprintf(f, "n: %#x\ne: %#x\n",
			k.N, k.E); err != nil {
			return
		}
	case *ecdsa.PrivateKey:
		if _, err = fmt.Fprintf(f, "curve: %s\nx: %#x\ny: %#x\nd: %#x\n",
			k.Params().Name,
			k.X, k.Y,
			k.D); err != nil {
			return
		}
	case *ecdsa.PublicKey:
		if _, err = fmt.Fprintf(f, "curve: %s\nx: %#x\ny: %#x\n",
			k.Params().Name,
			k.X, k.Y); err != nil {
			return
		}
	default:
		err = ErrUnsuitableKeyType
		return
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
