//go:build linux

// Package deps pre-declares dependencies needed by the full kpxcd project.
// These are imported with blank identifiers so go mod tidy keeps them.
package deps

import (
	_ "github.com/fxamacker/cbor/v2"
	_ "github.com/godbus/dbus/v5"
	_ "github.com/pquerna/otp"
)
