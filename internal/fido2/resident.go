//go:build linux

package fido2

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/fido2/hid"
	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

// passkeySnapshot clones entries under their database lock. RootEntries returns
// shallow values, whose slices may otherwise race an update or database lock.
func (s *Fido2Service) passkeySnapshot(db *dbpool.OpenDatabase) []gokeepasslib.Entry {
	db.RLock()
	defer db.RUnlock()
	if db.Locked {
		return nil
	}
	return s.passkeySnapshotLocked(db.Db)
}

// passkeySnapshotLocked is called only while the database content lock is held.
func (s *Fido2Service) passkeySnapshotLocked(kdb *gokeepasslib.Database) []gokeepasslib.Entry {
	if kdb == nil || kdb.Content == nil || kdb.Content.Root == nil {
		return nil
	}
	var entries []gokeepasslib.Entry
	var visit func([]gokeepasslib.Group)
	recycle := dbpool.RecycleBinUUIDForDB(kdb)
	visit = func(groups []gokeepasslib.Group) {
		for i := range groups {
			if dbpool.IsRecycled(&groups[i], recycle) {
				continue
			}
			for j := range groups[i].Entries {
				clone := groups[i].Entries[j].Clone()
				// Library Clone creates a new entry identity; snapshots must retain it.
				clone.UUID = groups[i].Entries[j].UUID
				entries = append(entries, clone)
			}
			visit(groups[i].Groups)
		}
	}
	visit(kdb.Content.Root.Groups)
	return entries
}

// persistRegistration implements the selected-database-only policy. Pool
// membership and database contents stay stable through the one target save.
// Database locks serialize this check with all in-process content writers.
// Other locked/unopened vaults are intentionally not inspected or unlocked.
func (s *Fido2Service) persistRegistration(target *dbpool.OpenDatabase, pk *PasskeyEntry, replace bool) error {
	return s.pool.UpdateAndSaveWithUnlockedDatabases(target, func(dbs map[*dbpool.OpenDatabase]*gokeepasslib.Database) error {
		var matchDB *dbpool.OpenDatabase
		var matchUUID string
		matches := 0
		handle, err := base64.RawURLEncoding.DecodeString(pk.UserHandle)
		if err != nil {
			return err
		}
		for db, kdb := range dbs {
			if !replace {
				continue
			}
			for _, entry := range s.passkeySnapshotLocked(kdb) {
				if entryContent(entry, KPEXPasskeyRPID, legacyPasskeyRPID) != pk.RPID {
					continue
				}
				existing, err := base64.RawURLEncoding.DecodeString(entryContent(entry, KPEXPasskeyHandle, legacyPasskeyHandle))
				if err != nil || len(existing) == 0 || !bytes.Equal(existing, handle) {
					continue
				}
				// Partial legacy data is not eligible for inferred repair.
				old, err := extractPasskeyFromEntry(&entry)
				if err != nil || old == nil {
					return fmt.Errorf("fido2: matching account has incomplete credential data")
				}
				matches++
				matchDB, matchUUID = db, fmt.Sprintf("%x", entry.UUID[:])
			}
		}
		if matches > 1 || (matches == 1 && matchDB != target) {
			return fmt.Errorf("fido2: ambiguous resident account ownership")
		}
		kdb := dbs[target]
		if matches == 0 {
			group := findOrCreatePasskeyGroup(kdb)
			entry := newPasskeyEntry(pk)
			pk.EntryUUID = fmt.Sprintf("%x", entry.UUID[:])
			group.Entries = append(group.Entries, entry)
			return nil
		}
		entry := findEntryByUUIDHex(&kdb.Content.Root.Groups, matchUUID)
		if entry == nil {
			return fmt.Errorf("fido2: replacement entry disappeared")
		}
		old, err := extractPasskeyFromEntry(entry)
		if err != nil {
			return err
		}
		if old == nil || old.RPID != pk.RPID {
			return fmt.Errorf("fido2: replacement identity changed")
		}
		existing, err := base64.RawURLEncoding.DecodeString(old.UserHandle)
		if err != nil || !bytes.Equal(existing, handle) {
			return fmt.Errorf("fido2: replacement identity changed")
		}
		// All validation precedes mutation: callback errors do not restore the root.
		// Replace credential fields only, retaining UUID, title, password, notes,
		// attachments, history and unrelated metadata on an imported KeePass entry.
		// Drop superseded legacy kpxcd fields so no stale private key or
		// credential ID remains on the entry.
		for _, key := range []string{legacyPasskeyRPID, legacyPasskeyRPName, legacyPasskeyUser, legacyPasskeyHandle, legacyPasskeyCredID, legacyPasskeyPrivKey} {
			if idx := entry.GetIndex(key); idx >= 0 {
				entry.Values = append(entry.Values[:idx], entry.Values[idx+1:]...)
			}
		}
		fresh := newPasskeyEntry(pk)
		for _, value := range fresh.Values {
			if value.Key == "Title" || value.Key == "UserName" || value.Key == "URL" || value.Key == "Password" {
				continue
			}
			setEntryValue(entry, value.Key, value.Value.Content, value.Value.Protected.Bool)
		}
		now := wrappers.Now()
		entry.Times.LastModificationTime = &now
		pk.EntryUUID = matchUUID
		return nil
	})
}

// residentCredentials captures identifier-only candidates with deterministic
// newest-created ordering. Missing timestamps sort oldest; UUIDs break ties.
func (s *Fido2Service) residentCredentials(rpID string) ([]hid.CredentialReference, error) {
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	type candidate struct {
		ref     hid.CredentialReference
		created time.Time
	}
	var candidates []candidate
	err := s.pool.WithUnlockedDatabases(func(dbs []*dbpool.OpenDatabase) error {
		for _, db := range dbs {
			for _, entry := range s.passkeySnapshot(db) {
				if entryContent(entry, KPEXPasskeyRPID, legacyPasskeyRPID) != rpID {
					continue
				}
				pk, err := extractPasskeyFromEntry(&entry)
				if err != nil {
					slog.Warn("fido2: skipping malformed passkey entry", "database", db.Name, "error", err)
					continue
				}
				if pk == nil {
					continue
				}
				if id, err := base64.RawURLEncoding.DecodeString(pk.CredentialID); err != nil || len(id) == 0 {
					return fmt.Errorf("fido2: invalid stored credential ID")
				}
				if handle, err := base64.RawURLEncoding.DecodeString(pk.UserHandle); err != nil || len(handle) == 0 {
					return fmt.Errorf("fido2: invalid stored user handle")
				}
				c := candidate{ref: hid.CredentialReference{DatabaseUUID: db.UUID, DatabaseInstance: db.InstanceID, EntryUUID: fmt.Sprintf("%x", entry.UUID[:]), RPID: rpID, CredentialID: pk.CredentialID, UserHandle: pk.UserHandle}}
				if created := entry.GetContent(KPEXPasskeyCreated); created != "" {
					var err error
					c.created, err = time.Parse(time.RFC3339Nano, created)
					if err != nil {
						return fmt.Errorf("fido2: invalid credential creation time: %w", err)
					}
				} else if entry.Times.CreationTime != nil {
					// Legacy/imported credentials have only the KeePass entry time.
					c.created = entry.Times.CreationTime.Time
				}
				candidates = append(candidates, c)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(candidates, func(a, b candidate) int {
		return cmp.Or(b.created.Compare(a.created), cmp.Compare(a.ref.DatabaseUUID, b.ref.DatabaseUUID), cmp.Compare(a.ref.EntryUUID, b.ref.EntryUUID))
	})
	refs := make([]hid.CredentialReference, len(candidates))
	for i := range candidates {
		refs[i] = candidates[i].ref
	}
	return refs, nil
}

// assertResident validates every original candidate, signs the selected key and
// saves its counter under the pool's ordered database-lock boundary. Independent
// content writers and pool lifecycle changes cannot invalidate any candidate
// between validation and save. No signature escapes a failed save.
func (s *Fido2Service) assertResident(ref hid.CredentialReference, original []hid.CredentialReference, hash []byte, up, uv bool) (hid.ResidentAssertion, error) {
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	var result hid.ResidentAssertion
	if !s.config.Enabled || len(hash) != 32 || ref.RPID == "" {
		return result, fmt.Errorf("fido2: invalid assertion request")
	}
	if len(original) == 0 || !slices.Contains(original, ref) {
		return result, ErrNoCredentials
	}
	// Resolve only the target pointer here; the authoritative validation below
	// rechecks membership, availability and identity while all locks are held.
	var target *dbpool.OpenDatabase
	err := s.pool.WithUnlockedDatabases(func(dbs []*dbpool.OpenDatabase) error {
		for _, db := range dbs {
			if db.UUID == ref.DatabaseUUID && db.InstanceID == ref.DatabaseInstance {
				target = db
				break
			}
		}
		return nil
	})
	if err != nil || target == nil {
		return result, ErrNoCredentials
	}
	err = s.pool.UpdateAndSaveWithUnlockedDatabases(target, func(dbs map[*dbpool.OpenDatabase]*gokeepasslib.Database) error {
		for _, candidate := range original {
			if candidate.RPID != ref.RPID {
				return ErrNoCredentials
			}
			found := false
			for db, kdb := range dbs {
				if db.UUID != candidate.DatabaseUUID || db.InstanceID != candidate.DatabaseInstance {
					continue
				}
				for _, entry := range s.passkeySnapshotLocked(kdb) {
					if fmt.Sprintf("%x", entry.UUID[:]) != candidate.EntryUUID {
						continue
					}
					pk, err := extractPasskeyFromEntry(&entry)
					if err != nil {
						return err
					}
					found = pk != nil && pk.RPID == candidate.RPID && pk.CredentialID == candidate.CredentialID && pk.UserHandle == candidate.UserHandle
				}
			}
			if !found {
				return ErrNoCredentials
			}
		}
		kdb := dbs[target]
		entry := findEntryByUUIDHex(&kdb.Content.Root.Groups, ref.EntryUUID)
		if entry == nil {
			return ErrNoCredentials
		}
		pk, err := extractPasskeyFromEntry(entry)
		if err != nil {
			return err
		}
		if pk == nil || pk.RPID != ref.RPID || pk.CredentialID != ref.CredentialID || pk.UserHandle != ref.UserHandle {
			return ErrNoCredentials
		}
		// Recycle-bin movement is removal from the eligible set as well.
		eligible := false
		var visit func([]gokeepasslib.Group)
		recycle := dbpool.RecycleBinUUIDForDB(kdb)
		visit = func(groups []gokeepasslib.Group) {
			for i := range groups {
				if dbpool.IsRecycled(&groups[i], recycle) {
					continue
				}
				for j := range groups[i].Entries {
					if groups[i].Entries[j].UUID == entry.UUID {
						eligible = true
					}
				}
				visit(groups[i].Groups)
			}
		}
		visit(kdb.Content.Root.Groups)
		if !eligible {
			return ErrNoCredentials
		}
		if pk.SignCount == ^uint32(0) {
			return fmt.Errorf("fido2: signature counter exhausted")
		}
		id, err := base64.RawURLEncoding.DecodeString(pk.CredentialID)
		if err != nil || len(id) == 0 {
			return fmt.Errorf("fido2: invalid credential ID")
		}
		handle, err := base64.RawURLEncoding.DecodeString(pk.UserHandle)
		if err != nil || len(handle) == 0 {
			return fmt.Errorf("fido2: invalid user handle")
		}
		flags := byte(0)
		if up {
			flags |= FlagUP
		}
		if uv {
			flags |= FlagUV
		}
		auth := buildAuthenticatorData(ref.RPID, flags, pk.SignCount+1, nil)
		signature, err := signWithPrivateKey(pk.PrivateKeyPEM, auth, hash)
		if err != nil {
			return err
		}
		result = hid.ResidentAssertion{CredentialID: id, UserHandle: handle, AuthData: auth, Signature: signature}
		if uv {
			result.Name, result.DisplayName = pk.Username, pk.DisplayName
		}
		setEntryValue(entry, KPEXPasskeyCounter, fmt.Sprintf("%d", pk.SignCount+1), false)
		now := wrappers.Now()
		entry.Times.LastModificationTime = &now
		return nil
	})
	if err != nil {
		return hid.ResidentAssertion{}, err
	}
	return result, nil
}
