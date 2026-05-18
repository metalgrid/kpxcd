//go:build linux

package secretservice

import (
	"github.com/godbus/dbus/v5"
)

// Properties implements org.freedesktop.DBus.Properties for Secret Service objects.
// It dispatches property reads to the correct underlying object.
type Properties struct {
	ss *SecretService
}

func NewProperties(ss *SecretService) *Properties {
	return &Properties{ss: ss}
}

func (p *Properties) Get(iface, property string) (dbus.Variant, *dbus.Error) {
	switch iface {
	case InterfaceService:
		return p.getServiceProp(property)
	case InterfaceCollection:
		// Collection properties need path context — handled via GetAll or
		// per-collection property objects. Fall through.
	case InterfaceItem:
		// Same — item properties need path context.
	}
	return dbus.MakeVariant(""), nil
}

func (p *Properties) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	switch iface {
	case InterfaceService:
		return p.getAllServiceProps()
	}
	return make(map[string]dbus.Variant), nil
}

func (p *Properties) Set(iface, property string, value dbus.Variant) *dbus.Error {
	// Read-only daemon — all properties are read-only.
	return nil
}

func (p *Properties) getServiceProp(property string) (dbus.Variant, *dbus.Error) {
	switch property {
	case "Collections":
		p.ss.mu.RLock()
		paths := make([]dbus.ObjectPath, 0, len(p.ss.collections))
		for path := range p.ss.collections {
			paths = append(paths, path)
		}
		p.ss.mu.RUnlock()
		return dbus.MakeVariant(paths), nil
	}
	return dbus.MakeVariant(""), nil
}

func (p *Properties) getAllServiceProps() (map[string]dbus.Variant, *dbus.Error) {
	v, err := p.getServiceProp("Collections")
	if err != nil {
		return nil, err
	}
	return map[string]dbus.Variant{
		"Collections": v,
	}, nil
}

// collectionProps returns all properties for a collection.
func collectionProps(coll *Collection) map[string]dbus.Variant {
	paths := coll.svc.itemsForCollection(coll.path)
	itemPaths := make([]dbus.ObjectPath, 0, len(paths))
	for _, item := range paths {
		itemPaths = append(itemPaths, item.Path())
	}

	return map[string]dbus.Variant{
		"Items":     dbus.MakeVariant(itemPaths),
		"Label":     dbus.MakeVariant(coll.Label()),
		"Locked":    dbus.MakeVariant(coll.Locked()),
		"Created":   dbus.MakeVariant(uint64(coll.Created())),
		"Modified":  dbus.MakeVariant(uint64(coll.Modified())),
	}
}

// itemProps returns all properties for an item.
func itemProps(item *Item) map[string]dbus.Variant {
	return map[string]dbus.Variant{
		"Locked":     dbus.MakeVariant(item.Locked()),
		"Label":      dbus.MakeVariant(item.Label()),
		"Attributes": dbus.MakeVariant(item.Attributes()),
		"Created":    dbus.MakeVariant(uint64(item.Created())),
		"Modified":   dbus.MakeVariant(uint64(item.Modified())),
	}
}

// collectionProperties is a per-collection DBus.Properties handler.
type collectionProperties struct {
	coll *Collection
}

func newCollectionProperties(coll *Collection) *collectionProperties {
	return &collectionProperties{coll: coll}
}

func (cp *collectionProperties) Get(iface, property string) (dbus.Variant, *dbus.Error) {
	if iface != InterfaceCollection {
		return dbus.MakeVariant(""), nil
	}
	props := collectionProps(cp.coll)
	if v, ok := props[property]; ok {
		return v, nil
	}
	return dbus.MakeVariant(""), nil
}

func (cp *collectionProperties) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	if iface != InterfaceCollection {
		return make(map[string]dbus.Variant), nil
	}
	return collectionProps(cp.coll), nil
}

func (cp *collectionProperties) Set(iface, property string, value dbus.Variant) *dbus.Error {
	return nil // read-only
}

// itemProperties is a per-item DBus.Properties handler.
type itemProperties struct {
	item *Item
}

func newItemProperties(item *Item) *itemProperties {
	return &itemProperties{item: item}
}

func (ip *itemProperties) Get(iface, property string) (dbus.Variant, *dbus.Error) {
	if iface != InterfaceItem {
		return dbus.MakeVariant(""), nil
	}
	props := itemProps(ip.item)
	if v, ok := props[property]; ok {
		return v, nil
	}
	return dbus.MakeVariant(""), nil
}

func (ip *itemProperties) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	if iface != InterfaceItem {
		return make(map[string]dbus.Variant), nil
	}
	return itemProps(ip.item), nil
}

func (ip *itemProperties) Set(iface, property string, value dbus.Variant) *dbus.Error {
	return nil // read-only
}
