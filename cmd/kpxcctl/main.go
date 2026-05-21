//go:build linux

// Package main implements the kpxcctl CLI client for the kpxcd daemon.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/godbus/dbus/v5"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/user/kpxcd/internal/config"
	"github.com/user/kpxcd/internal/pamcred"
	"github.com/user/kpxcd/internal/xdg"
	"golang.org/x/term"
)

const (
	busName    = "org.keepassxc.Daemon"
	objectPath = "/org/keepassxc/Daemon"
	iface      = "org.keepassxc.Daemon"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "unlock":
		cmdUnlock(args)
	case "lock":
		cmdLock(args)
	case "list":
		cmdList(args)
	case "get":
		cmdGet(args)
	case "ssh":
		cmdSSH(args)
	case "passkey":
		cmdPasskey(args)
	case "adopt-default":
		cmdAdoptDefault(args)
	case "setup-ssh":
		cmdSetupSSH(args)
	case "ping":
		cmdPing()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "kpxcctl: unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`kpxcctl — command-line client for kpxcd

Usage:
  kpxcctl <command> [arguments]

Commands:
  unlock [path]               Unlock the default or a specific database
  lock [uuid|name]           Lock a database (or all)
  list                       List unlocked databases
  get <uuid> <entry-path>    Get entry fields (password, username, TOTP)
  ssh list                   List SSH keys in the agent
  ssh add <uuid> <entry>    Add an SSH key to the agent
  ssh remove <fingerprint>  Remove an SSH key from the agent
  passkey create <uuid> <rpID> <username>  Create a new passkey
  passkey assert <rpID> <credID>            Assert a passkey
  adopt-default [--replace] <source.kdbx>   Copy source DB to the PAM default store and rekey it
  setup-ssh                  Configure SSH_AUTH_SOCK for the current user
  ping                       Check if daemon is alive
  help                       Show this help message`)
}

// connectDBus creates a connection to the session bus and returns an object proxy.
func connectDBus() (dbus.BusObject, *dbus.Conn, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, nil, fmt.Errorf("kpxcctl: failed to connect to session bus: %w", err)
	}
	obj := conn.Object(busName, dbus.ObjectPath(objectPath))
	return obj, conn, nil
}

// cmdSetupSSH configures SSH_AUTH_SOCK for the current user based on the
// daemon's ssh_mode setting.
//
// Agent mode: writes ~/.config/environment.d/kpxcd-ssh.conf to export
// SSH_AUTH_SOCK pointing to kpxcd's agent socket.
//
// Client mode: writes ~/.config/systemd/user/kpxcd.service.d/ssh-client.conf
// to pass SSH_AUTH_SOCK into the daemon from the session environment.
func cmdSetupSSH(args []string) {
	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl setup-ssh: failed to load config: %v\n", err)
		os.Exit(1)
	}

	switch cfg.Daemon.SSHMode {
	case "agent":
		setupSSHAgentMode(cfg)
	case "client", "proxy":
		setupSSHClientMode()
	default:
		fmt.Fprintf(os.Stderr, "kpxcctl setup-ssh: unknown ssh_mode %q\n", cfg.Daemon.SSHMode)
		os.Exit(1)
	}
}

func setupSSHAgentMode(cfg *config.Config) {
	// Resolve the socket path the same way the daemon does.
	socketPath := os.ExpandEnv(cfg.Daemon.SSHSocketPath)
	if !filepath.IsAbs(socketPath) {
		xdg := os.Getenv("XDG_RUNTIME_DIR")
		if xdg == "" {
			xdg = fmt.Sprintf("/run/user/%d", os.Getuid())
		}
		socketPath = filepath.Join(xdg, socketPath)
	}

	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, _ := os.UserHomeDir()
		configHome = filepath.Join(home, ".config")
	}
	confDir := filepath.Join(configHome, "environment.d")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl setup-ssh: failed to create %s: %v\n", confDir, err)
		os.Exit(1)
	}

	confPath := filepath.Join(confDir, "kpxcd-ssh.conf")
	content := fmt.Sprintf("SSH_AUTH_SOCK=%s\n", socketPath)
	if err := os.WriteFile(confPath, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl setup-ssh: failed to write %s: %v\n", confPath, err)
		os.Exit(1)
	}

	// Remove the client-mode drop-in if this user previously configured it.
	_ = os.Remove(filepath.Join(configHome, "systemd", "user", "kpxcd.service.d", "ssh-client.conf"))

	fmt.Printf("Configured SSH_AUTH_SOCK for agent mode.\n")
	fmt.Printf("  Written: %s\n", confPath)
	fmt.Printf("  SSH_AUTH_SOCK=%s\n", socketPath)
	fmt.Printf("\nLog out and back in for this to take effect.\n")
}

func setupSSHClientMode() {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, _ := os.UserHomeDir()
		configHome = filepath.Join(home, ".config")
	}

	dropinDir := filepath.Join(configHome, "systemd", "user", "kpxcd.service.d")
	if err := os.MkdirAll(dropinDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl setup-ssh: failed to create %s: %v\n", dropinDir, err)
		os.Exit(1)
	}

	dropinPath := filepath.Join(dropinDir, "ssh-client.conf")
	content := "[Service]\nPassEnvironment=SSH_AUTH_SOCK\n"
	if err := os.WriteFile(dropinPath, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl setup-ssh: failed to write %s: %v\n", dropinPath, err)
		os.Exit(1)
	}

	// Remove the agent-mode environment.d file if this user previously configured it.
	_ = os.Remove(filepath.Join(configHome, "environment.d", "kpxcd-ssh.conf"))

	fmt.Printf("Configured SSH_AUTH_SOCK passthrough for client mode.\n")
	fmt.Printf("  Written: %s\n", dropinPath)
	fmt.Printf("\nMake sure SSH_AUTH_SOCK is set in the systemd user manager environment.\n")
	fmt.Printf("For example: systemctl --user set-environment SSH_AUTH_SOCK=/run/user/$(id -u)/ssh-agent.sock\n")
	fmt.Printf("Then run: systemctl --user daemon-reload && systemctl --user restart kpxcd\n")
}

// cmdUnlock unlocks a database.
//
// Usage:
//
// 	kpxcctl unlock              Unlock the default database (PAM credential or password)
// 	kpxcctl unlock <path>       Unlock a specific database by password
func cmdUnlock(args []string) {
	if len(args) == 0 {
		cmdUnlockDefault()
	} else {
		cmdUnlockPath(args[0])
	}
}

// cmdUnlockDefault unlocks the default database. If the database uses PAM
// credentials, the user's login password is used to derive a key that unwraps
// the sealed age identity and decrypts the database password. Otherwise, a
// plain password prompt is used.
func cmdUnlockDefault() {
	defaultPath := xdg.DefaultDatabasePath()
	identityPath := xdg.DefaultIdentityPath()
	credentialPath := xdg.DefaultCredentialPath()

	// Try PAM credential chain if sealed identity and credential exist.
	if fileExists(identityPath) && fileExists(credentialPath) {
		loginPassword := readSecretPrompt("Login password: ")
		token := pamcred.DerivePAMToken([]byte(loginPassword))

		identity, err := pamcred.ReadSealedIdentity(identityPath, token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: failed to unseal identity (wrong password?): %v\n", err)
			os.Exit(1)
		}
		cred, err := pamcred.ReadSealedCredential(credentialPath, identity)
		if err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: failed to decrypt database credential: %v\n", err)
			os.Exit(1)
		}

		unlockViaDBus(defaultPath, cred.DBPassword)
		return
	}

	// No PAM credentials — prompt for database password directly.
	password := readSecretPrompt("Database password: ")
	unlockViaDBus(defaultPath, password)
}

// cmdUnlockPath unlocks a specific database by path with a password prompt.
func cmdUnlockPath(path string) {
	password := readSecretPrompt("Database password: ")
	unlockViaDBus(path, password)
}

// unlockViaDBus calls the daemon's UnlockDatabase over DBus.
func unlockViaDBus(path, password string) {
	obj, conn, err := connectDBus()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()

	variant := dbus.MakeVariant(password)
	result := obj.Call(iface+".UnlockDatabase", 0, path, "password", variant)
	if result.Err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl: failed to unlock database: %v\n", result.Err)
		os.Exit(1)
	}

	var unlocked bool
	if err := result.Store(&unlocked); err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl: unexpected response: %v\n", err)
		os.Exit(1)
	}

	if unlocked {
		fmt.Println("Database unlocked successfully")
	} else {
		fmt.Println("Failed to unlock database")
		os.Exit(1)
	}
}

// cmdLock locks a database.
func cmdLock(args []string) {
	obj, conn, err := connectDBus()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()

	if len(args) == 0 || args[0] == "all" {
		result := obj.Call(iface+".LockAll", 0)
		if result.Err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: failed to lock databases: %v\n", result.Err)
			os.Exit(1)
		}
		fmt.Println("All databases locked")
		return
	}

	uuid := args[0]
	result := obj.Call(iface+".LockDatabase", 0, uuid)
	if result.Err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl: failed to lock database: %v\n", result.Err)
		os.Exit(1)
	}

	var locked bool
	if err := result.Store(&locked); err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl: unexpected response: %v\n", err)
		os.Exit(1)
	}

	if locked {
		fmt.Println("Database locked successfully")
	} else {
		fmt.Println("Failed to lock database")
		os.Exit(1)
	}
}

// cmdList lists unlocked databases.
func cmdList(args []string) {
	obj, conn, err := connectDBus()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()

	result := obj.Call(iface+".ListDatabases", 0)
	if result.Err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl: failed to list databases: %v\n", result.Err)
		os.Exit(1)
	}

	var databases []map[string]dbus.Variant
	if err := result.Store(&databases); err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl: unexpected response: %v\n", err)
		os.Exit(1)
	}

	if len(databases) == 0 {
		fmt.Println("No databases unlocked")
		return
	}

	// Check for --json flag.
	jsonOutput := len(args) > 0 && args[0] == "--json"

	if jsonOutput {
		type dbInfo struct {
			UUID   string `json:"uuid"`
			Name   string `json:"name"`
			Path   string `json:"path"`
			Locked bool   `json:"locked"`
		}
		var infos []dbInfo
		for _, db := range databases {
			infos = append(infos, dbInfo{
				UUID:   getVariantString(db["uuid"]),
				Name:   getVariantString(db["name"]),
				Path:   getVariantString(db["path"]),
				Locked: getVariantBool(db["locked"]),
			})
		}
		data, _ := json.MarshalIndent(infos, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("%-36s %-20s %-10s %s\n", "UUID", "Name", "Locked", "Path")
	fmt.Println(strings.Repeat("-", 80))
	for _, db := range databases {
		fmt.Printf("%-36s %-20s %-10t %s\n",
			getVariantString(db["uuid"]),
			getVariantString(db["name"]),
			getVariantBool(db["locked"]),
			getVariantString(db["path"]))
	}
}

// cmdGet retrieves entry fields.
func cmdGet(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "kpxcctl get: missing uuid or entry path")
		os.Exit(1)
	}

	uuid := args[0]
	entryPath := args[1]

	obj, conn, err := connectDBus()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()

	result := obj.Call(iface+".GetEntry", 0, uuid, entryPath)
	if result.Err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl: failed to get entry: %v\n", result.Err)
		os.Exit(1)
	}

	var entry map[string]dbus.Variant
	if err := result.Store(&entry); err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl: unexpected response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Title:    %s\n", getVariantString(entry["title"]))
	fmt.Printf("Username: %s\n", getVariantString(entry["username"]))
	fmt.Printf("Password: %s\n", getVariantString(entry["password"]))
	fmt.Printf("URL:      %s\n", getVariantString(entry["url"]))
	fmt.Printf("TOTP:     %s\n", getVariantString(entry["totp"]))
}

// cmdSSH handles SSH key subcommands.
func cmdSSH(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "kpxcctl ssh: missing subcommand (list, add, remove)")
		os.Exit(1)
	}

	subcmd := args[0]
	subArgs := args[1:]

	obj, conn, err := connectDBus()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()

	switch subcmd {
	case "list":
		uuid := ""
		if len(subArgs) > 0 {
			uuid = subArgs[0]
		}
		result := obj.Call(iface+".SshListKeys", 0, uuid)
		if result.Err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: failed to list SSH keys: %v\n", result.Err)
			os.Exit(1)
		}
		var keys []map[string]dbus.Variant
		if err := result.Store(&keys); err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: unexpected response: %v\n", err)
			os.Exit(1)
		}
		if len(keys) == 0 {
			fmt.Println("No SSH keys loaded")
			return
		}
		fmt.Printf("%-50s %-20s %-15s %s\n", "Fingerprint", "Comment", "Type", "Entry")
		for _, key := range keys {
			fmt.Printf("%-50s %-20s %-15s %s\n",
				getVariantString(key["fingerprint"]),
				getVariantString(key["comment"]),
				getVariantString(key["type"]),
				getVariantString(key["entry_path"]))
		}

	case "add":
		if len(subArgs) < 2 {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh add: missing uuid or entry path")
			os.Exit(1)
		}
		uuid := subArgs[0]
		entryPath := subArgs[1]
		lifetime := uint32(0)
		confirm := false

		result := obj.Call(iface+".SshAddKey", 0, uuid, entryPath, lifetime, confirm)
		if result.Err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: failed to add SSH key: %v\n", result.Err)
			os.Exit(1)
		}
		fmt.Println("SSH key added successfully")

	case "remove":
		if len(subArgs) < 1 {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh remove: missing fingerprint")
			os.Exit(1)
		}
		fingerprint := subArgs[0]
		result := obj.Call(iface+".SshRemoveKey", 0, fingerprint)
		if result.Err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: failed to remove SSH key: %v\n", result.Err)
			os.Exit(1)
		}
		fmt.Println("SSH key removed successfully")

	default:
		fmt.Fprintf(os.Stderr, "kpxcctl ssh: unknown subcommand: %s\n", subcmd)
		os.Exit(1)
	}
}

// cmdPasskey handles passkey subcommands.
func cmdPasskey(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "kpxcctl passkey: missing subcommand (create, assert)")
		os.Exit(1)
	}

	subcmd := args[0]
	subArgs := args[1:]

	obj, conn, err := connectDBus()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()

	switch subcmd {
	case "create":
		if len(subArgs) < 3 {
			fmt.Fprintln(os.Stderr, "kpxcctl passkey create: missing uuid, rpID, or username")
			os.Exit(1)
		}
		uuid := subArgs[0]
		rpID := subArgs[1]
		userName := subArgs[2]
		userDisplayName := userName

		result := obj.Call(iface+".CreatePasskey", 0, uuid, rpID, rpID, userName, userDisplayName)
		if result.Err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: failed to create passkey: %v\n", result.Err)
			os.Exit(1)
		}

		var pkResult map[string]dbus.Variant
		if err := result.Store(&pkResult); err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: unexpected response: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Created passkey:\n")
		fmt.Printf("  Credential ID: %s\n", getVariantString(pkResult["credential_id"]))
		fmt.Printf("  Entry path:    %s\n", getVariantString(pkResult["entry_path"]))

	case "assert":
		if len(subArgs) < 2 {
			fmt.Fprintln(os.Stderr, "kpxcctl passkey assert: missing rpID or credentialID")
			os.Exit(1)
		}
		rpID := subArgs[0]
		credentialID := subArgs[1]
		challenge := "placeholder-challenge"
		origin := "https://" + rpID

		result := obj.Call(iface+".AssertPasskey", 0, rpID, credentialID, challenge, origin)
		if result.Err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: failed to assert passkey: %v\n", result.Err)
			os.Exit(1)
		}

		var assertResult map[string]dbus.Variant
		if err := result.Store(&assertResult); err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: unexpected response: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Assertion result:\n")
		fmt.Printf("  Authenticator data: %s\n", getVariantString(assertResult["authenticator_data"]))
		fmt.Printf("  Signature:          %s\n", getVariantString(assertResult["signature"]))
		fmt.Printf("  User handle:         %s\n", getVariantString(assertResult["user_handle"]))

	default:
		fmt.Fprintf(os.Stderr, "kpxcctl passkey: unknown subcommand: %s\n", subcmd)
		os.Exit(1)
	}
}

// cmdPing checks if the daemon is alive.
func cmdPing() {
	obj, conn, err := connectDBus()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()

	result := obj.Call(iface+".Ping", 0)
	if result.Err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl: daemon not responding: %v\n", result.Err)
		os.Exit(1)
	}

	var response string
	if err := result.Store(&response); err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl: unexpected response: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(response)
}

// Helper functions for extracting variant values.
func getVariantString(v dbus.Variant) string {
	switch val := v.Value().(type) {
	case string:
		return val
	default:
		return fmt.Sprintf("%v", val)
	}
}

func getVariantBool(v dbus.Variant) bool {
	if val, ok := v.Value().(bool); ok {
		return val
	}
	return false
}

// cmdAdoptDefault copies an existing KeePass database into kpxcd's default
// PAM-backed store and changes its KDBX password to a generated random secret
// sealed by the PAM/age credential chain.
func cmdAdoptDefault(args []string) {
	replace := false
	var source string
	for _, arg := range args {
		switch arg {
		case "--replace":
			replace = true
		default:
			if source == "" {
				source = arg
			} else {
				fmt.Fprintf(os.Stderr, "kpxcctl adopt-default: unexpected argument: %s\n", arg)
				os.Exit(1)
			}
		}
	}
	if source == "" {
		fmt.Fprintln(os.Stderr, "kpxcctl adopt-default: missing source .kdbx path")
		os.Exit(1)
	}

	defaultPath := xdg.DefaultDatabasePath()
	identityPath := xdg.DefaultIdentityPath()
	credentialPath := xdg.DefaultCredentialPath()

	if !replace {
		if fileExists(defaultPath) {
			fmt.Fprintf(os.Stderr, "kpxcctl: default database already exists: %s (use --replace to overwrite)\n", defaultPath)
			os.Exit(1)
		}
		if fileExists(credentialPath) {
			fmt.Fprintf(os.Stderr, "kpxcctl: default credential already exists: %s (use --replace to overwrite)\n", credentialPath)
			os.Exit(1)
		}
	}

	// If the daemon is running, lock the default database so it releases the
	// old file. After adopt, the next PAM login will unlock the new database.
	lockDefaultInDaemon()

	sourcePassword := readSecretPrompt("Source database password: ")
	loginPassword := readSecretPrompt("Login/PAM password to seal default credential: ")
	loginToken := pamcred.DerivePAMToken([]byte(loginPassword))

	identity, err := loadOrCreateIdentity(identityPath, loginToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl: failed to prepare age identity: %v\n", err)
		os.Exit(1)
	}

	cred, err := pamcred.NewRandomDBCredential(defaultPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl: failed to generate default DB credential: %v\n", err)
		os.Exit(1)
	}
	cred.CreatedAt = time.Now().UTC().Format(time.RFC3339)

	if err := copyAndRekeyDatabase(source, defaultPath, sourcePassword, cred.DBPassword, replace); err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl: failed to copy/rekey database: %v\n", err)
		os.Exit(1)
	}
	if err := pamcred.WriteSealedCredential(credentialPath, cred, identity.Recipient()); err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl: failed to write sealed credential: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Adopted %s as default database:\n", source)
	fmt.Printf("  Database:   %s\n", defaultPath)
	fmt.Printf("  Identity:   %s\n", identityPath)
	fmt.Printf("  Credential: %s\n", credentialPath)
}

func readSecretPrompt(prompt string) string {
	fmt.Print(prompt)
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl: failed to read secret: %v\n", err)
		os.Exit(1)
	}
	return string(b)
}

// lockDefaultInDaemon attempts to lock the default database in a running
// daemon via DBus. If the daemon is not running or the database is not open,
// this is a no-op.
func lockDefaultInDaemon() {
	obj, conn, err := connectDBus()
	if err != nil {
		return // daemon not running
	}
	defer conn.Close()

	// Find the default database UUID.
	result := obj.Call(iface+".ListDatabases", 0)
	if result.Err != nil {
		return
	}

	var dbs []map[string]dbus.Variant
	if err := result.Store(&dbs); err != nil {
		return
	}

	defaultPath := xdg.DefaultDatabasePath()
	for _, db := range dbs {
		if getVariantString(db["path"]) == defaultPath {
			uuid := getVariantString(db["uuid"])
			locked := false
			lockResult := obj.Call(iface+".LockDatabase", 0, uuid)
			_ = lockResult.Store(&locked)
			if locked {
				fmt.Fprintf(os.Stderr, "Locked default database in daemon (UUID: %s)\n", uuid)
			}
			return
		}
	}
}

func loadOrCreateIdentity(path string, loginToken []byte) (*age.X25519Identity, error) {
	if fileExists(path) {
		return pamcred.ReadSealedIdentity(path, loginToken)
	}
	identity, err := pamcred.GenerateIdentity()
	if err != nil {
		return nil, err
	}
	if err := pamcred.WriteSealedIdentity(path, identity, loginToken); err != nil {
		return nil, err
	}
	return identity, nil
}

func copyAndRekeyDatabase(sourcePath, destPath, sourcePassword, destPassword string, replace bool) error {
	f, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer f.Close()

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(sourcePassword)
	if err := gokeepasslib.NewDecoder(f).Decode(db); err != nil {
		return err
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		return err
	}
	db.Credentials = gokeepasslib.NewPasswordCredentials(destPassword)

	if err := xdg.EnsurePrivateDir(filepath.Dir(destPath)); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(destPath), "."+filepath.Base(destPath)+".adopt-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := db.LockProtectedEntries(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := gokeepasslib.NewEncoder(tmp).Encode(db); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if !replace && fileExists(destPath) {
		return fmt.Errorf("destination exists: %s", destPath)
	}
	return os.Rename(tmpName, destPath)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
