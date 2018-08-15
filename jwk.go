package keyremix

import (
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	"strconv"
	"strings"
)

type jwkFormat struct {
}

func (*jwkFormat) Serialize(key interface{}, args map[string]string) (output []byte, err error) {
	var jkey jwk.Key
	if jkey, err = jwk.New(key); err != nil {
		return
	}
	wrap := true
	if set, ok := args["set"]; ok {
		switch strings.ToLower(set) {
		case "t", "true", "y", "yes", "1":
			wrap = true
		case "f", "false", "n", "no", "0":
			wrap = false
		default:
			err = fmt.Errorf("invalid set argument")
			return
		}
	}
	var j interface{}
	if wrap {
		j = map[string][]interface{}{
			"keys": []interface{}{jkey},
		}
	} else {
		j = jkey
	}
	if indent, ok := args["indent"]; ok {
		var i int
		if i, err = strconv.Atoi(indent); err != nil {
			return
		}
		if output, err = json.MarshalIndent(j, "", fmt.Sprintf("%*s", i, "")); err != nil {
			return
		}
		output = append(output, '\n')
	} else {
		if output, err = json.Marshal(j); err != nil {
			return
		}
	}
	return
}

func (*jwkFormat) Deserialize(input []byte, args map[string]string) (key interface{}, rest []byte, err error) {
	i := 0
	if index, ok := args["index"]; ok {
		if i, err = strconv.Atoi(index); err != nil {
			return
		}
		if i < 0 {
			err = fmt.Errorf("negative key index")
			return
		}
	}
	var keySet *jwk.Set
	if keySet, err = jwk.Parse(input); err != nil {
		return
	}
	if i >= len(keySet.Keys) {
		err = fmt.Errorf("only %d keys found", len(keySet.Keys))
		return
	}
	if key, err = keySet.Keys[i].Materialize(); err != nil {
		return
	}
	return
}

func (*jwkFormat) Recognize(input []byte, args map[string]string) (fits Fit, err error) {
	var m map[string]interface{}
	if err = json.Unmarshal(input, &m); err != nil {
		fits = DoesNotFit
		return
	}
	fits = UnambiguousFit
	return
}

func (*jwkFormat) Name() string {
	return "jwk"
}

func (*jwkFormat) Description() string {
	return "RFC7517 JWK"
}

// Jwk is JWK format.
//
// See https://tools.ietf.org/html/rfc7517.
//
// Serialization argument: indent
//
// This is an integer giving the indent depth for JSON output.
// If unset, the output is a single line.
//
// Serialization argument: set
//
// If "true" then output is a JWK Set. This is the default.
// If "false" it is just the key.
//
// Deserialization argument: index
//
// This the index in the JWK Set to use. The default is 0.
// Raw JWKs are always at index 0.
var Jwk = &jwkFormat{}

func init() {
	registerKeyFormat(Jwk)
}
