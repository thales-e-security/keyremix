# keyremix

This is a simple tool to convert between key formats.

# Build

    dep ensure
    make
    ./keyremix --help

# Use

## Listing Formats

This subcommand displays recognized formats.

    $ keyremix formats
    jwk       RFC7517 JWK
    pkcs1     RFC8017/PKCS#1 format (RSA only)
    pkcs1der  RFC8017/PKCS#1 format (raw DER)
	[...]

## Converting Keys

This subcommand converts between formats.

    $ keyremix convert -i e512.crt -t jwk -T indent=2
    {
      "keys": [
        {
          "crv": "P-521",
          "kty": "EC",
          "x": "Afwd8BEgOWwUjTecj3FfBZTK2zkbSgrb8Wpjsnl8f6gm6hoK4HRyZHzr2LYPNQkjFJOndJObGHPNKIU5s48HwzJ_",
          "y": "MMmq4TGaqPb0kNiWCacWGmrwkE24nArit4C3Nv--AfEbK6d1VXQLKJZmFPhD92sin6TV6y4Scj5hl36_yObj-yQ"
        }
      ]
    }

The possible arguments are:

* `-i PATH` to set the input filename. The default is standard input.
* `-f FORMAT` to set the input format. The default is to guess.
* `-F NAME=VALUE` to set an input argument.
* `-o PATH` to set the output filename. The default is standard output.
* `-t FORMAT` to set the output format.
* `-T NAME=VALUE` to set an output argument.

Use the `formats` command to get a list of known formats.
See below for input and output arguments.

## Getting Public Keys

This is very similar to `convert` except that it extracts public key values
from private keys.

    $ keyremix public -i ecdsa-pkcs8.pem -t text
    curve: P-256
    x: 0xe813085693c472af2d56d01740a9d45a5d93b53c02697d05444dcfe5bb835cc
    y: 0xd27d598acbe5d9b5fbb52fd555fb3879b9a2eec9e8d476ac9ca60cc3d1ffd956

The possible arguments are:

* `-i PATH` to set the input filename. The default is standard input.
* `-f FORMAT` to set the input format. The default is to guess.
* `-F NAME=VALUE` to set an input argument.
* `-o PATH` to set the output filename. The default is standard output.
* `-t FORMAT` to set the output format. The default is based on the input format.
* `-T NAME=VALUE` to set an output argument.

Use the `formats` command to get a list of known formats.
See below for input and output arguments.

## Formats

Many formats have PEM variants (e.g. `pkcs1`) and DER variants (e.g. `pkcs1der`).
They differ only in whether PEM wrapping is used.

### `jwk`

[RFC7517](https://tools.ietf.org/html/rfc7517) JWK format.

* Inputs may be either single JWKs or JWK sets.
Where a JWK set is used, use `-F index=N` to select the Nth key.
An index of 0 means the first key.
* Outputs are JWK sets by default.
Use `-T set=false` to output just the key.
* Outputs are single-line by default.
Use `-T indent=N` to select multi-line output indentation of N spaces.

### `pkcs1` and `pkcs1der`

[PKCS#1/RFC8017](https://tools.ietf.org/html/rfc8017) format.
* Only RSA keys private and public can be used.

### `pkcs8` and `pksc8der`

[PKCS#8/RFC5208]( https://tools.ietf.org/html/rfc5208) format.
* Only RSA and ECDSA private keys can be used.

### `pkix` and `pkixder`

[RFC3279](https://tools.ietf.org/html/rfc3279) format.
* Only RSA and ECDSA public keys can be used.

### `text`

Textual representation of keys.
* Only usable as an output format.

### `x509` and `x509der`

X.509 certificate format.
* Only usable as an input format.
* Only RSA and ECDSA public keys can be used.

# General Remarks

* The set of key types and formats reflects what is easy to do with Go.
* Encryption and decryption of keys is not supported.
* Test coverage is a bit weak.
