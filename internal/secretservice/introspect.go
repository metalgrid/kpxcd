//go:build linux

package secretservice

import "github.com/godbus/dbus/v5"

// IntrospectData is the XML introspection data for DBus interfaces.

const (
	// ServiceIntrospectionXML is the introspection data for the Service interface.
	ServiceIntrospectionXML = `
<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node name="/org/freedesktop/secrets">
  <interface name="org.freedesktop.Secret.Service">
    <method name="OpenSession">
      <arg name="algorithm" type="s" direction="in"/>
      <arg name="input" type="v" direction="in"/>
      <arg name="output" type="v" direction="out"/>
      <arg name="result" type="o" direction="out"/>
    </method>
    <method name="CreateCollection">
      <arg name="properties" type="a{sv}" direction="in"/>
      <arg name="alias" type="s" direction="in"/>
      <arg name="collection" type="o" direction="out"/>
      <arg name="prompt" type="o" direction="out"/>
    </method>
    <method name="SearchItems">
      <arg name="attributes" type="a{ss}" direction="in"/>
      <arg name="results" type="ao" direction="out"/>
      <arg name="locked" type="ao" direction="out"/>
    </method>
    <method name="Unlock">
      <arg name="objects" type="ao" direction="in"/>
      <arg name="unlocked" type="ao" direction="out"/>
      <arg name="prompt" type="o" direction="out"/>
    </method>
    <method name="Lock">
      <arg name="objects" type="ao" direction="in"/>
      <arg name="locked" type="ao" direction="out"/>
      <arg name="prompt" type="o" direction="out"/>
    </method>
    <method name="GetSecrets">
      <arg name="items" type="ao" direction="in"/>
      <arg name="session" type="o" direction="in"/>
      <arg name="secrets" type="a{o(oayays)}" direction="out"/>
    </method>
    <method name="ReadAlias">
      <arg name="name" type="s" direction="in"/>
      <arg name="collection" type="o" direction="out"/>
    </method>
    <method name="SetAlias">
      <arg name="name" type="s" direction="in"/>
      <arg name="collection" type="o" direction="in"/>
    </method>
    <signal name="CollectionChanged">
      <arg name="collection" type="o"/>
    </signal>
    <signal name="CollectionCreated">
      <arg name="collection" type="o"/>
    </signal>
    <signal name="CollectionDeleted">
      <arg name="collection" type="o"/>
    </signal>
    <signal name="CollectionsChanged">
      <arg name="created" type="ao"/>
      <arg name="deleted" type="ao"/>
    </signal>
  </interface>
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect">
      <arg name="data" type="s" direction="out"/>
    </method>
  </interface>
  <interface name="org.freedesktop.DBus.Properties">
    <method name="Get">
      <arg name="interface" type="s" direction="in"/>
      <arg name="property" type="s" direction="in"/>
      <arg name="value" type="v" direction="out"/>
    </method>
    <method name="GetAll">
      <arg name="interface" type="s" direction="in"/>
      <arg name="properties" type="a{sv}" direction="out"/>
    </method>
    <method name="Set">
      <arg name="interface" type="s" direction="in"/>
      <arg name="property" type="s" direction="in"/>
      <arg name="value" type="v" direction="in"/>
    </method>
    <signal name="PropertiesChanged">
      <arg name="interface" type="s"/>
      <arg name="changed_properties" type="a{sv}"/>
      <arg name="invalidated_properties" type="as"/>
    </signal>
  </interface>
</node>`

	// CollectionIntrospectionXML is the introspection data for the Collection interface.
	CollectionIntrospectionXML = `
<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
  <interface name="org.freedesktop.Secret.Collection">
    <property name="Items" type="ao" access="read"/>
    <property name="Label" type="s" access="readwrite"/>
    <property name="Locked" type="b" access="read"/>
    <method name="Delete">
      <arg name="prompt" type="o" direction="out"/>
    </method>
    <method name="SearchItems">
      <arg name="attributes" type="a{sv}" direction="in"/>
      <arg name="results" type="ao" direction="out"/>
    </method>
  </interface>
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect">
      <arg name="data" type="s" direction="out"/>
    </method>
  </interface>
  <interface name="org.freedesktop.DBus.Properties">
    <method name="Get">
      <arg name="interface" type="s" direction="in"/>
      <arg name="property" type="s" direction="in"/>
      <arg name="value" type="v" direction="out"/>
    </method>
    <method name="GetAll">
      <arg name="interface" type="s" direction="in"/>
      <arg name="properties" type="a{sv}" direction="out"/>
    </method>
    <method name="Set">
      <arg name="interface" type="s" direction="in"/>
      <arg name="property" type="s" direction="in"/>
      <arg name="value" type="v" direction="in"/>
    </method>
  </interface>
</node>`

	// ItemIntrospectionXML is the introspection data for the Item interface.
	ItemIntrospectionXML = `
<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
  <interface name="org.freedesktop.Secret.Item">
    <property name="Locked" type="b" access="read"/>
    <property name="Attributes" type="a{ss}" access="read"/>
    <property name="Label" type="s" access="readwrite"/>
    <property name="Created" type="x" access="read"/>
    <property name="Modified" type="x" access="read"/>
    <method name="Delete">
      <arg name="prompt" type="o" direction="out"/>
    </method>
    <method name="GetSecret">
      <arg name="session" type="o" direction="in"/>
      <arg name="secret" type="(oayays)" direction="out"/>
    </method>
  </interface>
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect">
      <arg name="data" type="s" direction="out"/>
    </method>
  </interface>
  <interface name="org.freedesktop.DBus.Properties">
    <method name="Get">
      <arg name="interface" type="s" direction="in"/>
      <arg name="property" type="s" direction="in"/>
      <arg name="value" type="v" direction="out"/>
    </method>
    <method name="GetAll">
      <arg name="interface" type="s" direction="in"/>
      <arg name="properties" type="a{sv}" direction="out"/>
    </method>
    <method name="Set">
      <arg name="interface" type="s" direction="in"/>
      <arg name="property" type="s" direction="in"/>
      <arg name="value" type="v" direction="in"/>
    </method>
  </interface>
</node>`

	// SessionIntrospectionXML is the introspection data for the Session interface.
	SessionIntrospectionXML = `
<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
  <interface name="org.freedesktop.Secret.Session">
    <method name="Close"/>
  </interface>
</node>`

	// PromptIntrospectionXML is the introspection data for the Prompt interface.
	PromptIntrospectionXML = `
<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
  <interface name="org.freedesktop.Secret.Prompt">
    <method name="Prompt"/>
    <method name="Dismiss"/>
    <signal name="Completed">
      <arg name="dismissed" type="b"/>
      <arg name="result" type="v"/>
    </signal>
  </interface>
</node>`
)

// Introspectable implements org.freedesktop.DBus.Introspectable for the service.
type Introspectable struct {
	ss *SecretService
}

// NewIntrospectable creates a new Introspectable for the service.
func NewIntrospectable(ss *SecretService) *Introspectable {
	return &Introspectable{ss: ss}
}

// Introspect returns the XML introspection data.
func (i *Introspectable) Introspect() (string, *dbus.Error) {
	return ServiceIntrospectionXML, nil
}

// IntrospectableCollection implements introspection for collections.
type IntrospectableCollection struct{}

// NewIntrospectableCollection creates a new collection introspectable.
func NewIntrospectableCollection() *IntrospectableCollection {
	return &IntrospectableCollection{}
}

// Introspect returns the collection introspection XML.
func (i *IntrospectableCollection) Introspect() (string, *dbus.Error) {
	return CollectionIntrospectionXML, nil
}

// IntrospectableItem implements introspection for items.
type IntrospectableItem struct{}

// NewIntrospectableItem creates a new item introspectable.
func NewIntrospectableItem() *IntrospectableItem {
	return &IntrospectableItem{}
}

// Introspect returns the item introspection XML.
func (i *IntrospectableItem) Introspect() (string, *dbus.Error) {
	return ItemIntrospectionXML, nil
}

// Properties implements org.freedesktop.DBus.Properties for the service.
type Properties struct {
	ss *SecretService
}

// NewProperties creates a new Properties handler for the service.
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
