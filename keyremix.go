package keyremix

import (
	"errors"
)

// Fit is an enumeration of possible input fit types.
type Fit int

const (
	// DoesNotFit is returned by KeyFormat.Recognize if the input definitely does not fit.
	DoesNotFit Fit = iota

	// AmbiguousFit is returned by KeyFormat.Recognize if the input fits but other formats could also reasonably fit.
	// For instance, this could be used by DER files.
	AmbiguousFit

	// UnambiguousFit is returned by KeyFormat.Recognize if the input fits and no other format could reasonably fit.
	// For instance, this might be used with PEM files that have an explicit key type.
	UnambiguousFit
)

// KeyFormat represents a key format.
type KeyFormat interface {
	// Serialize converts a key to this format.
	//
	// args is a collection of format-dependent parameters.
	Serialize(key interface{}, args map[string]string) (output []byte, err error)

	// Deserialize converts bytes in this format to a key.
	//
	// args is a collection of format-dependent parameters.
	// rest is anything left over after the parse.
	Deserialize(input []byte, args map[string]string) (key interface{}, rest []byte, err error)

	// Recognize returns an indicator of how well the input fits the format.
	//
	// Is is intended to do only a lightweight parse.
	// For instance it need not completely deserialize binary data to see if it fits a given ASN.1 syntax.
	//
	// args is a collection of format-dependent parameters (possibly aimed at different formats).
	// err may optionally be set (if fits==false) to document why the key was not recognized.
	Recognize(input []byte, args map[string]string) (fits Fit, err error)

	// Name returns the name of this format.
	Name() string

	// Description returns the description of this format
	Description() string
}

// ErrUnsuitableKeyType is returned when the key type is not suitable for the output format,
// or in some cases when the input is not recognizable.
var ErrUnsuitableKeyType = errors.New("unsuitable key type")

// ErrPasswordRequired is returned when a password is required.
var ErrPasswordRequired = errors.New("password required")

// ErrNotImplemented is returned when functionality is missing.
var ErrNotImplemented = errors.New("not implemented")

// KeyFormats is the collection of known key formats.
var KeyFormats = map[string]KeyFormat{}

// registerKeyFormat registers a key format.
// Conventionally it is called from init() functions.
func registerKeyFormat(kf KeyFormat) {
	KeyFormats[kf.Name()] = kf
}
