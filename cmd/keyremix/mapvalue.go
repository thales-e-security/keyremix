package main

import (
	"fmt"
	"strings"
)

// mapValue is a pflags.Value that adds strings to a map
type mapValue map[string]string

func (m mapValue) String() string {
	return ""
}

func (m mapValue) Set(v string) (err error) {
	bits := strings.SplitN(v, "=", 2)
	if len(bits) != 2 {
		err = fmt.Errorf("malformed argment '%s'", v)
		return
	}
	m[bits[0]] = bits[1]
	return
}

func (m mapValue) Type() string {
	return "map"
}
