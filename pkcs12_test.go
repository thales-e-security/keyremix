package keyremix

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"math/big"
	"os"
	"testing"
)

func TestPkcs12(t *testing.T) {
	t.Run("Deserialize", func(t *testing.T) {
		var rest []byte
		var err error
		var key interface{}
		args := map[string]string{
			"password":    "password",
			"certificate": "TestPkcs12Deserialize.crt",
		}
		defer os.Remove("TestPkcs12Deserialize.crt")
		key, rest, err = Pkcs12.Deserialize([]byte(rsaP12), args)
		require.NoError(t, err)
		switch k := key.(type) {
		case *rsa.PrivateKey:
			var N big.Int
			N.SetString("00bd88b15962861535504f977d9e4d7313a83631f91f4d7db7b0c7153117c10cbe703b289d611a443f8d21f967334822bb09758caa61403644e0059a425ee6284aefa9c2d5741dd1c473916ab55b9497e248e6e990e9c06dfa2888be1e271e73bd0cc12f83185fe1b61b31de9cdc27b74e1db8445dd28e07231ad8bb60fe268b7b", 16)
			assert.Equal(t, 65537, k.E)
			assert.Equal(t, N, *k.N)
		default:
			t.Errorf("wrong key type: %T", key)
		}
		assert.Equal(t, 0, len(rest))
		// Check that the certificate looks right
		var cert []byte
		cert, err = ioutil.ReadFile("TestPkcs12Deserialize.crt")
		require.NoError(t, err)
		var b *pem.Block
		b, rest = pem.Decode(cert)
		assert.Equal(t, "CERTIFICATE", b.Type)
		_, err = x509.ParseCertificate(b.Bytes)
		assert.NoError(t, err)
	})
	t.Run("Serialize", func(t *testing.T) {
		generateTestKeys()
		var err error
		// Need a certificate too
		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
		}
		var cert []byte
		cert, err = x509.CreateCertificate(rand.Reader, &template, &template, rsa1024.Public(), rsa1024)
		require.NoError(t, err)
		b := pem.Block{Type: "CERTIFICATE", Headers: nil, Bytes: cert}
		certPem := pem.EncodeToMemory(&b)
		require.NoError(t, ioutil.WriteFile("TestPkcs12Serialize.crt", certPem, 0666))
		defer os.Remove("TestPkcs12Serialize.crt")
		var rest, output []byte
		args := map[string]string{
			"password":    "insecure",
			"certificate": "TestPkcs12Serialize.crt",
		}
		output, err = Pkcs12.Serialize(rsa1024, args)
		require.NoError(t, err)
		os.Remove("TestPkcs12Serialize.crt")
		var key2i interface{}
		key2i, rest, err = Pkcs12.Deserialize(output, args)
		require.NoError(t, err)
		assert.Equal(t, 0, len(rest))
		key2 := key2i.(*rsa.PrivateKey)
		assert.Equal(t, rsa1024.N, key2.N)
		assert.Equal(t, rsa1024.E, key2.E)
		assert.Equal(t, rsa1024.D, key2.D)
		assert.Equal(t, rsa1024.Primes[0], key2.Primes[0])
		assert.Equal(t, rsa1024.Primes[1], key2.Primes[1])
		var writtenCert []byte
		writtenCert, err = ioutil.ReadFile("TestPkcs12Serialize.crt")
		require.NoError(t, err)
		require.Equal(t, certPem, writtenCert)
	})

}
