//go:build linux

package dbpool

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/user/kpxcd/internal/xdg"
)

// CreateDatabase creates a new KDBX4 database at path with mode 0600. It never
// overwrites an existing file.
func CreateDatabase(path, password string) error {
	if err := xdg.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("dbpool: create database directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("dbpool: database already exists: %s", path)
		}
		return fmt.Errorf("dbpool: create database: %w", err)
	}
	defer f.Close()

	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion4())
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	if db.Content != nil && db.Content.Root != nil && len(db.Content.Root.Groups) > 0 {
		db.Content.Root.Groups[0].Name = "Default"
		db.Content.Root.Groups[0].Entries = nil
	}

	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("dbpool: encode new database: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("dbpool: fsync new database: %w", err)
	}
	return nil
}
