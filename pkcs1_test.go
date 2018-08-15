package keyremix

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestPkcs1Pem(t *testing.T) {
	t.Run("Deserialize", func(t *testing.T) {
		var rest []byte
		var err error
		var key interface{}
		key, rest, err = Pkcs1Pem.Deserialize([]byte(rsaPkcs1Pem), nil)
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
	})
	t.Run("Recognize", func(t *testing.T) {
		var err error
		var fit Fit
		fit, err = Pkcs1Pem.Recognize([]byte(rsaPkcs1Pem), nil)
		require.NoError(t, err)
		assert.Equal(t, UnambiguousFit, fit)
	})
	t.Run("Serialize", func(t *testing.T) {
		var err error
		var key *rsa.PrivateKey
		key, err = rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, err)
		var rest, output []byte
		output, err = Pkcs1Pem.Serialize(key, nil)
		require.NoError(t, err)
		var key2i interface{}
		key2i, rest, err = Pkcs1Pem.Deserialize(output, nil)
		require.NoError(t, err)
		assert.Equal(t, 0, len(rest))
		key2 := key2i.(*rsa.PrivateKey)
		assert.Equal(t, key.N, key2.N)
		assert.Equal(t, key.E, key2.E)
		assert.Equal(t, key.D, key2.D)
		assert.Equal(t, key.Primes[0], key2.Primes[0])
		assert.Equal(t, key.Primes[1], key2.Primes[1])
	})
}

func TestPkcs1Der(t *testing.T) {
	t.Run("Deserialize", func(t *testing.T) {
		var rest []byte
		var err error
		var key interface{}
		key, rest, err = Pkcs1Der.Deserialize(rsaPkcs1Der, nil)
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
	})
	t.Run("Recognize", func(t *testing.T) {
		var err error
		var fit Fit
		fit, err = Pkcs1Der.Recognize(rsaPkcs1Der, nil)
		require.NoError(t, err)
		assert.Equal(t, AmbiguousFit, fit)
	})
	t.Run("Serialize", func(t *testing.T) {
		var err error
		var key *rsa.PrivateKey
		key, err = rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, err)
		var rest, output []byte
		output, err = Pkcs1Der.Serialize(key, nil)
		require.NoError(t, err)
		var key2i interface{}
		key2i, rest, err = Pkcs1Der.Deserialize(output, nil)
		require.NoError(t, err)
		assert.Equal(t, 0, len(rest))
		key2 := key2i.(*rsa.PrivateKey)
		assert.Equal(t, key.N, key2.N)
		assert.Equal(t, key.E, key2.E)
		assert.Equal(t, key.D, key2.D)
		assert.Equal(t, key.Primes[0], key2.Primes[0])
		assert.Equal(t, key.Primes[1], key2.Primes[1])
	})
}
