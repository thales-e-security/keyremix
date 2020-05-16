package keyremix

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestPkcs8Pem(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		t.Run("Deserialize", func(t *testing.T) {
			var rest []byte
			var err error
			var key interface{}
			key, rest, err = Pkcs8Pem.Deserialize([]byte(rsaPkcs8Pem), nil)
			require.NoError(t, err)
			switch k := key.(type) {
			case *rsa.PrivateKey:
				var N big.Int
				N.SetString("009fa7ddb6f2df34e70986e7d29a5de8d779377a59f808f8692858a07a41bb537dfff14aaecc88a7f8ca547322c2563b297f6c6c92e08acb668128bf0aa2c6ec8ed68246293ce88f0ad825dd976795ec6d6d1e6f41412a8f2fcb5c515b35b93df785be4fbf816ce3b8acc976f72611e8a1a318cf734d14c7998699c42832b9f5df", 16)
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
			fit, err = Pkcs8Pem.Recognize([]byte(rsaPkcs8Pem), nil)
			require.NoError(t, err)
			assert.Equal(t, UnambiguousFit, fit)
		})
		t.Run("Serialize", func(t *testing.T) {
			generateTestKeys()
			var err error
			var rest, output []byte
			output, err = Pkcs8Pem.Serialize(rsa1024, nil)
			require.NoError(t, err)
			var key2i interface{}
			key2i, rest, err = Pkcs8Pem.Deserialize(output, nil)
			require.NoError(t, err)
			assert.Equal(t, 0, len(rest))
			key2 := key2i.(*rsa.PrivateKey)
			assert.Equal(t, rsa1024.N, key2.N)
			assert.Equal(t, rsa1024.E, key2.E)
			assert.Equal(t, rsa1024.D, key2.D)
			assert.Equal(t, rsa1024.Primes[0], key2.Primes[0])
			assert.Equal(t, rsa1024.Primes[1], key2.Primes[1])
		})
	})
	t.Run("EC", func(t *testing.T) {
		t.Run("Deserialize", func(t *testing.T) {
			var rest []byte
			var err error
			var key interface{}
			key, rest, err = Pkcs8Pem.Deserialize([]byte(ecdsaPkcs8Pem), nil)
			require.NoError(t, err)
			switch k := key.(type) {
			case *ecdsa.PrivateKey:
				var D big.Int
				D.SetString("f34887c2d41c7a17656d0cc605f1544c82e880bc13c881a34648d0659040ee32", 16)
				assert.Equal(t, "P-256", k.Curve.Params().Name)
				assert.Equal(t, D, *k.D)
			default:
				t.Errorf("wrong key type: %T", key)
			}
			assert.Equal(t, 0, len(rest))
		})
		t.Run("Recognize", func(t *testing.T) {
			var err error
			var fit Fit
			fit, err = Pkcs8Pem.Recognize([]byte(ecdsaPkcs8Pem), nil)
			require.NoError(t, err)
			assert.Equal(t, UnambiguousFit, fit)
		})
		t.Run("Serialize", func(t *testing.T) {
			generateTestKeys()
			var err error
			var rest, output []byte
			output, err = Pkcs8Pem.Serialize(ecdsa384, nil)
			require.NoError(t, err)
			var key2i interface{}
			key2i, rest, err = Pkcs8Pem.Deserialize(output, nil)
			require.NoError(t, err)
			assert.Equal(t, 0, len(rest))
			key2 := key2i.(*ecdsa.PrivateKey)
			assert.Equal(t, ecdsa384.D, key2.D)
			assert.Equal(t, ecdsa384.Curve, key2.Curve)
			assert.Equal(t, ecdsa384.X, key2.X)
			assert.Equal(t, ecdsa384.Y, key2.Y)
		})
	})
}

func TestPkcs8Der(t *testing.T) {
	t.Run("Deserialize", func(t *testing.T) {
		var rest []byte
		var err error
		var key interface{}
		key, rest, err = Pkcs8Der.Deserialize(rsaPkcs8Der, nil)
		require.NoError(t, err)
		switch k := key.(type) {
		case *rsa.PrivateKey:
			var N big.Int
			N.SetString("009fa7ddb6f2df34e70986e7d29a5de8d779377a59f808f8692858a07a41bb537dfff14aaecc88a7f8ca547322c2563b297f6c6c92e08acb668128bf0aa2c6ec8ed68246293ce88f0ad825dd976795ec6d6d1e6f41412a8f2fcb5c515b35b93df785be4fbf816ce3b8acc976f72611e8a1a318cf734d14c7998699c42832b9f5df", 16)
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
		fit, err = Pkcs8Der.Recognize(rsaPkcs8Der, nil)
		require.NoError(t, err)
		assert.Equal(t, AmbiguousFit, fit)
	})
	t.Run("Serialize", func(t *testing.T) {
		var err error
		var rest, output []byte
		output, err = Pkcs8Der.Serialize(rsa1024, nil)
		require.NoError(t, err)
		var key2i interface{}
		key2i, rest, err = Pkcs8Der.Deserialize(output, nil)
		require.NoError(t, err)
		assert.Equal(t, 0, len(rest))
		key2 := key2i.(*rsa.PrivateKey)
		assert.Equal(t, rsa1024.N, key2.N)
		assert.Equal(t, rsa1024.E, key2.E)
		assert.Equal(t, rsa1024.D, key2.D)
		assert.Equal(t, rsa1024.Primes[0], key2.Primes[0])
		assert.Equal(t, rsa1024.Primes[1], key2.Primes[1])
	})
}
