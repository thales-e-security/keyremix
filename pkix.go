package keyremix

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type pkix struct {
	Pem bool
}

func (p *pkix) Serialize(key interface{}, args map[string]string) (output []byte, err error) {
	if _, ok := args["password"]; ok {
		err = ErrNotImplemented
		return
	}
	var name string
	switch k := key.(type) {
	case *rsa.PublicKey:
		output, err = x509.MarshalPKIXPublicKey(k)
		name = "PUBLIC KEY"
	case *ecdsa.PublicKey:
		output, err = x509.MarshalPKIXPublicKey(k)
		name = "PUBLIC KEY"
	default:
		err = ErrUnsuitableKeyType
		return
	}
	if p.Pem {
		b := pem.Block{Type: name, Headers: nil, Bytes: output}
		output = pem.EncodeToMemory(&b)
	}
	return
}

func (p *pkix) Deserialize(input []byte, args map[string]string) (key interface{}, rest []byte, err error) {
	if p.Pem {
		var b *pem.Block
		b, rest = pem.Decode(input)
		input = b.Bytes
		switch b.Type {
		case "PUBLIC KEY":
			key, err = x509.ParsePKIXPublicKey(input)
		default:
			err = ErrUnsuitableKeyType
		}
	} else {
		key, err = x509.ParsePKIXPublicKey(input)
	}
	return
}

func (p *pkix) Recognize(input []byte, args map[string]string) (fit Fit, err error) {
	if p.Pem {
		b, _ := pem.Decode(input)
		if b == nil {
			fit = DoesNotFit
			return
		}
		switch b.Type {
		case "PUBLIC KEY":
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

func (p *pkix) Name() string {
	if p.Pem {
		return "pkix"
	}
	return "pkixder"
}

func (p *pkix) Description() string {
	if p.Pem {
		return "RFC3279/PKIX format (public keys only)"
	}
	return "RFC3279/PKIX format (raw DER)"
}

// PkixPem is PKIX format, with PEM encoding.
//
// Only RSA and ECDSA public keys are supported. See https://tools.ietf.org/html/rfc3279 and https://tools.ietf.org/html/rfc7468.
var PkixPem = &pkix{Pem: true}

// PkixDer is PKIX format, with DER encoding.
//
// Only RSA and ECDSA public keys are supported.  See https://tools.ietf.org/html/rfc3279.
var PkixDer = &pkix{Pem: false}

func init() {
	registerKeyFormat(PkixPem)
	registerKeyFormat(PkixDer)
}
