package keyremix

import (
	"crypto/x509"
	"encoding/pem"
)

type x509cert struct {
	Pem bool
}

func (x *x509cert) Serialize(key interface{}, args map[string]string) (output []byte, err error) {
	err = ErrUnsuitableKeyType
	return
}

func (x *x509cert) Deserialize(input []byte, args map[string]string) (key interface{}, rest []byte, err error) {
	var cert *x509.Certificate
	if x.Pem {
		var b *pem.Block
		b, rest = pem.Decode(input)
		input = b.Bytes
		switch b.Type {
		case "CERTIFICATE":
			if cert, err = x509.ParseCertificate(input); err != nil {
				return
			}
		default:
			err = ErrUnsuitableKeyType
		}
	} else {
		if cert, err = x509.ParseCertificate(input); err != nil {
			return
		}
	}
	key = cert.PublicKey
	return
}

func (x *x509cert) Recognize(input []byte, args map[string]string) (fit Fit, err error) {
	if x.Pem {
		b, _ := pem.Decode(input)
		if b == nil {
			fit = DoesNotFit
			return
		}
		switch b.Type {
		case "CERTIFICATE":
			fit = UnambiguousFit
			return
		default:
			fit = DoesNotFit
			return
		}
	} else {
		// TODO we could do a simple 'is it like DER' test.
		fit = AmbiguousFit
	}
	return
}

func (x *x509cert) Name() string {
	if x.Pem {
		return "x509"
	}
	return "x509der"
}

func (x *x509cert) Description() string {
	if x.Pem {
		return "X.509 certificate format (public key input only)"
	}
	return "X.509 certificate format (raw DER)"
}

// x509Pem is X.509 certificate format, with PEM encoding.
//
// Only RSA and ECDSA public keys are supported.
var x509Pem = &x509cert{Pem: true}

// x509Pem is X.509 certificate format, with DER encoding.
//
// Only RSA and ECDSA public keys are supported.
var x509Der = &x509cert{Pem: false}

func init() {
	registerKeyFormat(x509Pem)
	registerKeyFormat(x509Der)
}
