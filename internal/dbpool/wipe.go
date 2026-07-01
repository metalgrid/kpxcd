//go:build linux

package dbpool

import (
	"github.com/metalgrid/kpxcd/internal/security"
	"github.com/tobischo/gokeepasslib/v3"
)

// wipeDatabaseContent zeros sensitive decrypted data inside a database.
// It is best-effort: Go strings cannot be reliably zeroed in place, so we
// replace them with empty strings and clear byte buffers. The Content pointer
// is nilled by the caller after this function returns.
func wipeDatabaseContent(db *gokeepasslib.Database) {
	if db == nil {
		return
	}

	if db.Credentials != nil {
		security.Wipe(db.Credentials.Passphrase)
		security.Wipe(db.Credentials.Key)
		security.Wipe(db.Credentials.Windows)
		db.Credentials = nil
	}

	if db.Content == nil {
		return
	}

	content := db.Content
	if content.Meta != nil {
		for i := range content.Meta.Binaries {
			security.Wipe(content.Meta.Binaries[i].Content)
			content.Meta.Binaries[i].Content = nil
		}
		wipeCustomData(content.Meta.CustomData)
		content.Meta.DefaultUserName = ""
	}

	wipeGroups(content.Root.Groups)
}

func wipeGroups(groups []gokeepasslib.Group) {
	for i := range groups {
		g := &groups[i]
		g.Name = ""
		g.Notes = ""
		g.LastTopVisibleEntry = ""

		for j := range g.Entries {
			wipeEntry(&g.Entries[j])
		}
		wipeGroups(g.Groups)
	}
}

func wipeEntry(e *gokeepasslib.Entry) {
	e.ForegroundColor = ""
	e.BackgroundColor = ""
	e.OverrideURL = ""
	e.Tags = ""

	for i := range e.Values {
		e.Values[i].Value.Content = ""
	}
	for i := range e.Binaries {
		e.Binaries[i].Name = ""
	}
	wipeCustomData(e.CustomData)

	for i := range e.Histories {
		for j := range e.Histories[i].Entries {
			wipeEntry(&e.Histories[i].Entries[j])
		}
	}
}

func wipeCustomData(items []gokeepasslib.CustomData) {
	for i := range items {
		items[i].Value = ""
	}
}
