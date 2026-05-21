//go:build linux

package daemon

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/pamcred"
	"github.com/metalgrid/kpxcd/internal/security"
	"github.com/metalgrid/kpxcd/internal/xdg"
)

func (app *DaemonApp) hasPAMDatabase() bool {
	for _, db := range app.cfg.Databases {
		if db.AutoUnlock && db.UnlockCredential == "pam" {
			return true
		}
	}
	return false
}

func (app *DaemonApp) defaultDatabase() *config.DatabaseConfig {
	for i := range app.cfg.Databases {
		if app.cfg.Databases[i].Default {
			return &app.cfg.Databases[i]
		}
	}
	if len(app.cfg.Databases) > 0 {
		return &app.cfg.Databases[0]
	}
	return nil
}

func (app *DaemonApp) isDatabaseOpen(path string) bool {
	for _, db := range app.pool.List() {
		if db.Path == path && !db.Locked {
			return true
		}
	}
	return false
}

func (app *DaemonApp) unlockOrBootstrapWithPAM(db config.DatabaseConfig, token []byte) error {
	identityPath := xdg.DefaultIdentityPath()
	credentialPath := xdg.DefaultCredentialPath()

	identityExists := fileExists(identityPath)
	credentialExists := fileExists(credentialPath)
	dbExists := fileExists(db.Path)

	var cred pamcred.DBCredential
	if identityExists && credentialExists {
		identity, err := pamcred.ReadSealedIdentity(identityPath, token)
		if err != nil {
			return fmt.Errorf("unwrap age identity: %w", err)
		}
		cred, err = pamcred.ReadSealedCredential(credentialPath, identity)
		if err != nil {
			return fmt.Errorf("decrypt database credential: %w", err)
		}
		if cred.DBPath != db.Path {
			slog.Warn("pam credential DB path differs from config", "credential_path", cred.DBPath, "config_path", db.Path)
		}
		if !dbExists {
			if err := dbpool.CreateDatabase(db.Path, cred.DBPassword); err != nil {
				return fmt.Errorf("create missing default database: %w", err)
			}
		}
		return app.openWithPassword(db, cred.DBPassword)
	}

	if dbExists {
		return fmt.Errorf("default database exists but sealed PAM identity/credential is missing; refusing to modify existing database")
	}
	if identityExists != credentialExists {
		return fmt.Errorf("incomplete PAM credential state: identity_exists=%t credential_exists=%t", identityExists, credentialExists)
	}

	identity, err := pamcred.GenerateIdentity()
	if err != nil {
		return fmt.Errorf("generate age identity: %w", err)
	}
	cred, err = pamcred.NewRandomDBCredential(db.Path)
	if err != nil {
		return fmt.Errorf("generate database credential: %w", err)
	}
	if err := dbpool.CreateDatabase(db.Path, cred.DBPassword); err != nil {
		return fmt.Errorf("create default database: %w", err)
	}
	if err := pamcred.WriteSealedIdentity(identityPath, identity, token); err != nil {
		return fmt.Errorf("write sealed age identity: %w", err)
	}
	if err := pamcred.WriteSealedCredential(credentialPath, cred, identity.Recipient()); err != nil {
		return fmt.Errorf("write sealed database credential: %w", err)
	}
	slog.Info("created default kpxcd database and PAM-sealed credential", "path", db.Path)
	return app.openWithPassword(db, cred.DBPassword)
}

func (app *DaemonApp) openWithPassword(db config.DatabaseConfig, password string) error {
	ss, err := security.NewSecureString(password)
	if err != nil {
		return err
	}
	defer ss.Destroy()
	uuid, err := app.pool.Open(db.Path, dbpool.PasswordCredential(ss))
	if err != nil {
		return err
	}
	slog.Info("auto-unlocked database", "name", db.Name, "uuid", uuid)
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
