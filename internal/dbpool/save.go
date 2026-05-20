//go:build linux

package dbpool

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/tobischo/gokeepasslib/v3"
)

// FileFingerprint captures the on-disk identity and content hash of a database
// at the moment it was unlocked or last saved by kpxcd. It is used for
// optimistic conflict detection before writes; no long-lived database FD or
// advisory lock is held.
type FileFingerprint struct {
	Dev    uint64
	Ino    uint64
	Size   int64
	MTime  int64
	CTime  int64
	SHA256 string
}

// FingerprintFile computes a fingerprint for path.
func FingerprintFile(path string) (FileFingerprint, error) {
	info, err := os.Stat(path)
	if err != nil {
		return FileFingerprint{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return FileFingerprint{}, fmt.Errorf("unsupported stat type %T", info.Sys())
	}

	f, err := os.Open(path)
	if err != nil {
		return FileFingerprint{}, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return FileFingerprint{}, err
	}

	return FileFingerprint{
		Dev:    uint64(stat.Dev),
		Ino:    stat.Ino,
		Size:   info.Size(),
		MTime:  stat.Mtim.Sec,
		CTime:  stat.Ctim.Sec,
		SHA256: hex.EncodeToString(h.Sum(nil)),
	}, nil
}

// Equal returns true if both fingerprints represent the same file content and
// inode metadata.
func (f FileFingerprint) Equal(other FileFingerprint) bool {
	return f.Dev == other.Dev &&
		f.Ino == other.Ino &&
		f.Size == other.Size &&
		f.MTime == other.MTime &&
		f.CTime == other.CTime &&
		f.SHA256 == other.SHA256
}

// UpdateAndSave applies mutate while holding the database write lock, then
// atomically saves the KDBX file if the on-disk file still matches the last
// known fingerprint. If another process changed the file, the write is refused.
func (o *OpenDatabase) UpdateAndSave(mutate func(db *gokeepasslib.Database) error) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.Locked || o.Db == nil || o.Db.Content == nil {
		return fmt.Errorf("dbpool: database %s is locked", o.UUID)
	}
	current, err := FingerprintFile(o.Path)
	if err != nil {
		return fmt.Errorf("dbpool: fingerprint before update: %w", err)
	}
	if !o.Fingerprint.Equal(current) {
		return fmt.Errorf("dbpool: refusing to update %s: database changed on disk", o.Path)
	}
	var originalRoot *gokeepasslib.RootData
	if o.Db.Content != nil && o.Db.Content.Root != nil {
		originalRoot = cloneRootData(o.Db.Content.Root)
	}
	if mutate != nil {
		if err := mutate(o.Db); err != nil {
			return err
		}
	}
	if err := o.saveLocked(); err != nil {
		if originalRoot != nil && o.Db.Content != nil {
			o.Db.Content.Root = originalRoot
		}
		return err
	}
	return nil
}

// Save writes the current in-memory database to disk using optimistic conflict
// detection. Most callers should prefer UpdateAndSave so mutation and save are
// serialized under one lock.
func (o *OpenDatabase) Save() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.saveLocked()
}

func (o *OpenDatabase) saveLocked() error {
	current, err := FingerprintFile(o.Path)
	if err != nil {
		return fmt.Errorf("dbpool: fingerprint before save: %w", err)
	}
	if !o.Fingerprint.Equal(current) {
		return fmt.Errorf("dbpool: refusing to save %s: database changed on disk", o.Path)
	}

	// gokeepasslib's Encoder expects protected values to be in locked form: it
	// unlocks them to establish stream order, then locks them again for XML
	// output. kpxcd keeps entries unlocked while serving clients, so convert to
	// locked form before Encode and restore unlocked form afterwards.
	if err := o.Db.LockProtectedEntries(); err != nil {
		return fmt.Errorf("dbpool: lock protected entries before save: %w", err)
	}
	if err := atomicEncode(o.Path, o.Db, o.Fingerprint); err != nil {
		// Encoder leaves protected entries locked for writing. Restore the
		// unlocked in-memory representation even on failure so live clients keep
		// working after a failed save attempt.
		_ = o.Db.UnlockProtectedEntries()
		return err
	}
	if err := o.Db.UnlockProtectedEntries(); err != nil {
		return fmt.Errorf("dbpool: unlock protected entries after save: %w", err)
	}

	fp, err := FingerprintFile(o.Path)
	if err != nil {
		return fmt.Errorf("dbpool: fingerprint after save: %w", err)
	}
	o.Fingerprint = fp
	return nil
}

func cloneRootData(root *gokeepasslib.RootData) *gokeepasslib.RootData {
	clone := &gokeepasslib.RootData{
		Groups:         make([]gokeepasslib.Group, len(root.Groups)),
		DeletedObjects: make([]gokeepasslib.DeletedObjectData, len(root.DeletedObjects)),
	}
	for i := range root.Groups {
		clone.Groups[i] = root.Groups[i].Clone()
	}
	copy(clone.DeletedObjects, root.DeletedObjects)
	return clone
}

func atomicEncode(path string, db *gokeepasslib.Database, expected FileFingerprint) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("dbpool: stat %s: %w", path, err)
	}

	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("dbpool: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("dbpool: chmod temp file: %w", err)
	}

	if err := gokeepasslib.NewEncoder(tmp).Encode(db); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("dbpool: encode temp database: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("dbpool: fsync temp database: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("dbpool: close temp database: %w", err)
	}

	current, err := FingerprintFile(path)
	if err != nil {
		return fmt.Errorf("dbpool: fingerprint before rename: %w", err)
	}
	if !expected.Equal(current) {
		return fmt.Errorf("dbpool: refusing to save %s: database changed during save", path)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("dbpool: rename temp database: %w", err)
	}

	if dirFD, err := os.Open(dir); err == nil {
		_ = dirFD.Sync()
		_ = dirFD.Close()
	}
	return nil
}
