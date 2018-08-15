package keyremix

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestJwk(t *testing.T) {
	t.Run("Pub", func(t *testing.T) {
		var err error
		var key interface{}
		var rest []byte
		key, rest, err = Jwk.Deserialize([]byte(ecpuba1), nil)
		require.NoError(t, err)
		switch k := key.(type) {
		case *ecdsa.PublicKey:
			assert.Equal(t, "P-256", k.Curve.Params().Name)
		default:
			t.Errorf("wrong key type: %T", key)
		}
		require.Equal(t, 0, len(rest))
	})
	t.Run("Priv", func(t *testing.T) {
		var err error
		var key interface{}
		var rest []byte
		key, rest, err = Jwk.Deserialize([]byte(ecpriva2), nil)
		require.NoError(t, err)
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			assert.Equal(t, "P-256", k.Curve.Params().Name)
		default:
			t.Errorf("wrong key type: %T", key)
		}
		require.Equal(t, 0, len(rest))
		key, rest, err = Jwk.Deserialize([]byte(ecpriva2), map[string]string{"index": "1"})
		require.NoError(t, err)
		switch k := key.(type) {
		case *rsa.PrivateKey:
			assert.Equal(t, 65537, k.E)
		default:
			t.Errorf("wrong key type: %T", key)
		}
		require.Equal(t, 0, len(rest))
	})
}
