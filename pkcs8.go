package keyremix

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type pkcs8 struct {
	Pem bool
}

func (p *pkcs8) Serialize(key interface{}, args map[string]string) (output []byte, err error) {
	if _, ok := args["password"]; ok {
		err = ErrNotImplemented
		return
	}
	var name string
	switch k := key.(type) {
	case *rsa.PrivateKey:
		output, err = x509.MarshalPKCS8PrivateKey(k)
		name = "PRIVATE KEY"
	case *ecdsa.PrivateKey:
		output, err = x509.MarshalPKCS8PrivateKey(k)
		name = "PRIVATE KEY"
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

func (p *pkcs8) Deserialize(input []byte, args map[string]string) (key interface{}, rest []byte, err error) {
	if p.Pem {
		var b *pem.Block
		b, rest = pem.Decode(input)
		input = b.Bytes
		switch b.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(input)
		default:
			err = ErrUnsuitableKeyType
		}
	} else {
		key, err = x509.ParsePKCS8PrivateKey(input)
	}
	return
}

func (p *pkcs8) Recognize(input []byte, args map[string]string) (fit Fit, err error) {
	if p.Pem {
		b, _ := pem.Decode(input)
		if b == nil {
			fit = DoesNotFit
			return
		}
		switch b.Type {
		case "PRIVATE KEY":
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

func (p *pkcs8) Name() string {
	if p.Pem {
		return "pkcs8"
	}
	return "pkcs8der"
}

func (p *pkcs8) Description() string {
	if p.Pem {
		return "RFC5208/PKCS#8 format (private keys only)"
	}
	return "RFC5208/PKCS#8 format (raw DER)"
}

// Pkcs8Pem is PKCS#8 format, with PEM encoding.
//
// Only RSA and ECDSA private keys are supported. See https://tools.ietf.org/html/rfc5208.
var Pkcs8Pem = &pkcs8{Pem: true}

// Pkcs8Der is PKCS#8 format, with DER encoding.
//
// Only RSA and ECDSA private keys are supported. See https://tools.ietf.org/html/rfc5208.
var Pkcs8Der = &pkcs8{Pem: false}

func init() {
	registerKeyFormat(Pkcs8Pem)
	registerKeyFormat(Pkcs8Der)
}
