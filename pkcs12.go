package keyremix

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"git.tesfabric.com/ignite/xcrypto/pkcs12"
	"io/ioutil"
)

type pkcs12Format struct {
}

func (*pkcs12Format) Serialize(key interface{}, args map[string]string) (output []byte, err error) {
	var password string
	var ok bool
	// pkcs12 library requires encryption
	if password, ok = args["password"]; !ok {
		err = ErrPasswordRequired
		return
	}
	e := pkcs12.NewEncoder()
	// TODO iteration count
	// TODO salt length
	if err = e.AddKey(password, true, key); err != nil {
		return
	}
	var certpath string
	if certpath, ok = args["certificate"]; ok {
		var cert []byte
		if cert, err = ioutil.ReadFile(certpath); err != nil {
			return
		}
		var b *pem.Block
		b, _ = pem.Decode(cert)
		if b == nil {
			err = fmt.Errorf("cannot parse certificate")
			return
		}
		switch b.Type {
		case "CERTIFICATE":
			if err = e.CloseSafe(password, true); err != nil {
				return
			}
			if err = e.AddCertificate(b.Bytes); err != nil {
				return
			}
		default:
			err = fmt.Errorf("cannot parse certificate")
			return
		}

	}
	if err = e.CloseSafe(password, true); err != nil {
		return
	}
	if output, err = e.ClosePfx(password, true); err != nil {
		return
	}
	return
}

func (*pkcs12Format) Deserialize(input []byte, args map[string]string) (key interface{}, rest []byte, err error) {
	var password string
	var ok bool
	// pkcs12 library requires encryption
	if password, ok = args["password"]; !ok {
		err = ErrPasswordRequired
		return
	}
	var cert *x509.Certificate
	if key, cert, err = pkcs12.Decode(input, password); err != nil {
		return
	}
	var certpath string
	if certpath, ok = args["certificate"]; ok {
		b := pem.Block{Type: "CERTIFICATE", Headers: nil, Bytes: cert.Raw}
		if err = ioutil.WriteFile(certpath, pem.EncodeToMemory(&b), 0666); err != nil {
			return
		}
	}
	return
}

func (*pkcs12Format) Recognize(input []byte, args map[string]string) (fit Fit, err error) {
	// TODO we could do a simple 'is it like DER' test.
	fit = AmbiguousFit
	return
}

func (*pkcs12Format) Name() string {
	return "pkcs12"
}

func (*pkcs12Format) Description() string {
	return "RFC7292/PFX/PKCS#12 format"
}

// Pkcs12 is PKCS#12 (PFX) format.
//
// Only RSA and ECDSA private keys are supported.
// Only PFX files containing one key and one certificate are supported.
// See https://tools.ietf.org/html/rfc7292.
//
// (De-)Serialization argument: password
//
// The decryption/encryption password.
// Required.
//
// Serialization argument: certificate
//
// The filename of the certificate to include.
// Required.
//
// Deserialization argument: certificate
//
// The filename to write any certificate found.
// Optional.
var Pkcs12 = &pkcs12Format{}

func init() {
	registerKeyFormat(Pkcs12)
}
