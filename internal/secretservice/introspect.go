//go:build linux

package secretservice

import "github.com/godbus/dbus/v5"

// Properties implements org.freedesktop.DBus.Properties for all Secret Service objects.
type Properties struct {
	ss *SecretService
}

// NewProperties creates a new Properties handler.
func NewProperties(ss *SecretService) *Properties {
	return &Properties{ss: ss}
}

// Get returns a property value.
func (p *Properties) Get(iface, property string) (dbus.Variant, *dbus.Error) {
	return dbus.MakeVariant(""), nil
}

// GetAll returns all properties.
func (p *Properties) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	return make(map[string]dbus.Variant), nil
}

// Set sets a property value.
func (p *Properties) Set(iface, property string, value dbus.Variant) *dbus.Error {
	return nil
}
