//go:build linux

package secretservice

import (
	"fmt"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/tobischo/gokeepasslib/v3"
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
		"Items":    dbus.MakeVariant(itemPaths),
		"Label":    dbus.MakeVariant(coll.Label()),
		"Locked":   dbus.MakeVariant(coll.Locked()),
		"Created":  dbus.MakeVariant(coll.Created()),
		"Modified": dbus.MakeVariant(coll.Modified()),
	}
}

// itemProps returns all properties for an item.
func itemProps(item *Item) map[string]dbus.Variant {
	return map[string]dbus.Variant{
		"Locked":     dbus.MakeVariant(item.Locked()),
		"Label":      dbus.MakeVariant(item.Label()),
		"Attributes": dbus.MakeVariant(item.Attributes()),
		"Created":    dbus.MakeVariant(item.Created()),
		"Modified":   dbus.MakeVariant(item.Modified()),
	}
}

// propertiesIntrospectData returns the standard org.freedesktop.DBus.Properties
// interface description for introspection documents.
func propertiesIntrospectData() introspect.Interface {
	return introspect.Interface{
		Name: "org.freedesktop.DBus.Properties",
		Methods: []introspect.Method{
			{Name: "Get", Args: []introspect.Arg{
				{Name: "interface", Type: "s", Direction: "in"},
				{Name: "property", Type: "s", Direction: "in"},
				{Name: "value", Type: "v", Direction: "out"},
			}},
			{Name: "GetAll", Args: []introspect.Arg{
				{Name: "interface", Type: "s", Direction: "in"},
				{Name: "properties", Type: "a{sv}", Direction: "out"},
			}},
			{Name: "Set", Args: []introspect.Arg{
				{Name: "interface", Type: "s", Direction: "in"},
				{Name: "property", Type: "s", Direction: "in"},
				{Name: "value", Type: "v", Direction: "in"},
			}},
		},
	}
}

// collectionIntrospectProperties returns the property descriptions for a
// Secret Service collection.
func collectionIntrospectProperties() []introspect.Property {
	return []introspect.Property{
		{Name: "Items", Type: "ao", Access: "read"},
		{Name: "Label", Type: "s", Access: "read"},
		{Name: "Locked", Type: "b", Access: "read"},
		{Name: "Created", Type: "x", Access: "read"},
		{Name: "Modified", Type: "x", Access: "read"},
	}
}

// itemIntrospectProperties returns the property descriptions for a Secret
// Service item.
func itemIntrospectProperties() []introspect.Property {
	return []introspect.Property{
		{Name: "Locked", Type: "b", Access: "read"},
		{Name: "Attributes", Type: "a{ss}", Access: "read"},
		{Name: "Label", Type: "s", Access: "read"},
		{Name: "Created", Type: "x", Access: "read"},
		{Name: "Modified", Type: "x", Access: "read"},
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
	if iface != InterfaceItem {
		return nil
	}
	uuid := entryUUIDString(ip.item.entry)
	switch property {
	case "Label":
		label, ok := value.Value().(string)
		if !ok {
			return dbus.NewError("org.freedesktop.DBus.Error.InvalidArgs", []interface{}{"Label must be a string"})
		}
		if err := ip.item.db.UpdateAndSave(func(db *gokeepasslib.Database) error {
			entry := findEntryPtrByUUID(db.Content.Root.Groups, uuid)
			if entry == nil {
				return fmt.Errorf("secretservice: item not found: %s", uuid)
			}
			setEntryValue(entry, "Title", label, false)
			return nil
		}); err != nil {
			return dbus.NewError(ErrIsLocked, []interface{}{err.Error()})
		}
	case "Attributes":
		attrs, ok := value.Value().(map[string]string)
		if !ok {
			return dbus.NewError("org.freedesktop.DBus.Error.InvalidArgs", []interface{}{"Attributes must be a{ss}"})
		}
		if err := ip.item.db.UpdateAndSave(func(db *gokeepasslib.Database) error {
			entry := findEntryPtrByUUID(db.Content.Root.Groups, uuid)
			if entry == nil {
				return fmt.Errorf("secretservice: item not found: %s", uuid)
			}
			applyEntryAttributes(entry, attrs)
			return nil
		}); err != nil {
			return dbus.NewError(ErrIsLocked, []interface{}{err.Error()})
		}
	}
	return nil
}
