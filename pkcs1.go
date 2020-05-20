package keyremix

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type pkcs1 struct {
	Pem bool
}

func (p *pkcs1) Serialize(key interface{}, args map[string]string) (output []byte, err error) {
	if _, ok := args["password"]; ok {
		err = ErrNotImplemented
		return
	}
	var name string
	switch k := key.(type) {
	case *rsa.PrivateKey:
		output = x509.MarshalPKCS1PrivateKey(k)
		name = "RSA PRIVATE KEY"
	case *rsa.PublicKey:
		output = x509.MarshalPKCS1PublicKey(k)
		name = "RSA PUBLIC KEY"
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

func (p *pkcs1) Deserialize(input []byte, args map[string]string) (key interface{}, rest []byte, err error) {
	if p.Pem {
		// With PEM, we can rely on the type.
		var b *pem.Block
		b, rest = pem.Decode(input)
		input = b.Bytes
		switch b.Type {
		case "RSA PUBLIC KEY":
			key, err = x509.ParsePKCS1PublicKey(input)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(input)
		default:
			err = ErrUnsuitableKeyType
		}
	} else {
		// For raw DER, we just try each possibility in order.
		key, err = x509.ParsePKCS1PublicKey(input)
		if err != nil {
			key, err = x509.ParsePKCS1PrivateKey(input)
		}
	}
	return
}

func (p *pkcs1) Recognize(input []byte, args map[string]string) (fit Fit, err error) {
	if p.Pem {
		b, _ := pem.Decode(input)
		if b == nil {
			fit = DoesNotFit
			return
		}
		switch b.Type {
		case "RSA PUBLIC KEY", "RSA PRIVATE KEY":
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

func (p *pkcs1) Name() string {
	if p.Pem {
		return "pkcs1"
	}
	return "pkcs1der"
}

func (p *pkcs1) Description() string {
	if p.Pem {
		return "RFC8017/PKCS#1 format (RSA only)"
	}
	return "RFC8017/PKCS#1 format (raw DER)"
}

// Pkcs1Pem is PKCS#1 format, with PEM encoding.
//
// RSA private keys use https://tools.ietf.org/html/rfc8017 A.1.2 RSAPrivateKey, and RSA public keys use A.1.1 RSAPublicKey.
var Pkcs1Pem = &pkcs1{Pem: true}

// Pkcs1Der is PKCS#1 format, with DER encoding.
//
// RSA private keys use https://tools.ietf.org/html/rfc8017 A.1.2 RSAPrivateKey, and RSA public keys use A.1.1 RSAPublicKey.
var Pkcs1Der = &pkcs1{Pem: false}

func init() {
	registerKeyFormat(Pkcs1Pem)
	registerKeyFormat(Pkcs1Der)
}
