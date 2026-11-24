//go:build linux

// Package main implements the kpxcctl CLI client for the kpxcd daemon.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/godbus/dbus/v5"

	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/fido2"
	"github.com/metalgrid/kpxcd/internal/pamcred"
	"github.com/metalgrid/kpxcd/internal/security"
	"github.com/metalgrid/kpxcd/internal/sshagent"
	"github.com/metalgrid/kpxcd/internal/xdg"
	"github.com/tobischo/gokeepasslib/v3"
	"golang.org/x/crypto/ssh"
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
  get <uuid> <entry-path>    Get safe entry fields (title, username, URL)
  ssh list [uuid]            List SSH keys loaded in the agent
  ssh add <uuid> <entry>     Add an SSH key from a database entry to the agent
  ssh remove <fingerprint>   Remove an SSH key from the agent
  ssh scan [uuid]            Scan database(s) for SSH key entries
  ssh show <fingerprint>     Show details of a loaded SSH key
  ssh generate <uuid> <entry> [--type rsa|ed25519|ecdsa] [--bits N] [--comment text]
                             Generate a new SSH key and store it in the database
  ssh import [uuid]             Menu: import keys found in ~/.ssh (skips existing)
  ssh import <uuid> <entry> <file>
                             Import one key file into the database
  ssh autoload [uuid]          Menu: choose which keys auto-load at unlock
  ssh autoload <uuid> <entry> on|off [--override-deny]
                             Set/clear auto-load for one entry
  ssh export [uuid]              Menu: export a stored key to OpenSSH format (polkit-gated)
  ssh export <uuid> <entry> <file> [--force] [--no-passphrase]
                             Export one key; encrypted with a passphrase unless --no-passphrase
  ssh diag                   Show SSH agent diagnostics
  passkey list                             List stored passkeys
  passkey create <uuid> <rpID> <username> [displayName]
                                           Create a passkey (polkit-gated)
  passkey remove <credentialID>            Remove a passkey (polkit-gated)
  passkey import <uuid> <bitwarden.json> [--dry-run]
                                           Import passkeys from a Bitwarden JSON export
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
//	kpxcctl unlock              Unlock the default database (PAM credential or password)
//	kpxcctl unlock <path>       Unlock a specific database by password
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

	// No sealed PAM state — offer to bootstrap it: derive the token from
	// the login password and hand it to the daemon over the PAM socket,
	// exactly like the PAM module does at login. The daemon then creates
	// the missing default database (or unseals + unlocks an existing one).
	if fileExists(defaultPath) {
		// An unsealed database file exists; the plain password path below
		// is the right tool, and bootstrap would refuse to overwrite it.
		password := readSecretPrompt("Database password: ")
		unlockViaDBus(defaultPath, password)
		return
	}

	fmt.Println("No sealed PAM state found; bootstrapping the default database.")
	fmt.Println("The login password seals the database credential (never stored in the clear).")
	loginPassword := readSecretPrompt("Login password: ")
	token := pamcred.DerivePAMToken([]byte(loginPassword))
	defer security.Wipe(token)
	if err := sendPAMToken(token); err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl: bootstrap failed (daemon running?): %v\n", err)
		os.Exit(1)
	}

	// The PAM handoff is fire-and-forget; confirm the outcome by polling
	// the daemon until the database shows up in its pool.
	obj2, conn2, err := connectDBus()
	if err == nil {
		defer conn2.Close()
		for i := 0; i < 15; i++ {
			call := obj2.Call(iface+".ListDatabases", 0)
			if call.Err == nil {
				var dbs []map[string]dbus.Variant
				if call.Store(&dbs) == nil && len(dbs) > 0 {
					fmt.Println("Default database created and unlocked. On your next login the PAM hook unlocks it automatically.")
					return
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	fmt.Fprintf(os.Stderr, "kpxcctl: token sent, but the daemon did not report an unlocked database; check `journalctl --user -u kpxcd`\n")
	os.Exit(1)
}

// sendPAMToken sends a derived token over the PAM socket — the same
// handshake the PAM module performs during session setup.
func sendPAMToken(token []byte) error {
	socketPath, err := xdg.PAMSocketPath()
	if err != nil {
		return err
	}
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", socketPath, err)
	}
	defer conn.Close()
	if _, err := conn.Write(token); err != nil {
		return fmt.Errorf("send token: %w", err)
	}
	return nil
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
	fmt.Printf("URL:      %s\n", getVariantString(entry["url"]))
}

// cmdSSH handles SSH key subcommands.
func cmdSSH(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "kpxcctl ssh: missing subcommand (list, add, remove, scan, show)")
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
	case "autoload":
		cmdSSHAutoload(obj, subArgs)
		return
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

	case "generate":
		if len(subArgs) < 2 {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh generate: missing uuid or entry path")
			os.Exit(1)
		}
		uuid := subArgs[0]
		entryPath := subArgs[1]
		keyType := "ed25519"
		bits := uint32(0)
		comment := ""
		for i := 2; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "--type":
				if i+1 < len(subArgs) {
					keyType = subArgs[i+1]
					i++
				}
			case "--bits":
				if i+1 < len(subArgs) {
					var b int
					fmt.Sscanf(subArgs[i+1], "%d", &b)
					bits = uint32(b)
					i++
				}
			case "--comment":
				if i+1 < len(subArgs) {
					comment = subArgs[i+1]
					i++
				}
			}
		}
		result := obj.Call(iface+".SshGenerateKey", 0, uuid, entryPath, keyType, bits, comment)
		if result.Err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: failed to generate SSH key: %v\n", result.Err)
			os.Exit(1)
		}
		fmt.Printf("SSH key generated and stored in entry %q\n", entryPath)

	case "import":
		if len(subArgs) == 0 {
			cmdSSHImportMenu(obj, nil)
			return
		}
		if len(subArgs) < 3 {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh import: missing uuid, entry path, or key file")
			os.Exit(1)
		}
		uuid := subArgs[0]
		entryPath := subArgs[1]
		keyFile := subArgs[2]
		deleteAfter := false
		for i := 3; i < len(subArgs); i++ {
			if subArgs[i] == "--delete-after" {
				deleteAfter = true
			}
		}
		keyData, err := os.ReadFile(keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: failed to read key file: %v\n", err)
			os.Exit(1)
		}
		// Passphrase is prompted, never taken from argv (visible in ps).
		passphrase := ""
		if _, perr := sshagent.ParsePrivateKey(keyData, ""); perr != nil {
			if _, ok := perr.(*ssh.PassphraseMissingError); ok {
				passphrase = readSecretPrompt(fmt.Sprintf("Passphrase for %s: ", keyFile))
			}
		}
		result := obj.Call(iface+".SshImportKey", 0, uuid, entryPath, keyData, passphrase)
		if result.Err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: failed to import SSH key: %v\n", result.Err)
			os.Exit(1)
		}
		if deleteAfter {
			if err := os.Remove(keyFile); err != nil {
				fmt.Fprintf(os.Stderr, "kpxcctl: imported but failed to delete source file: %v\n", err)
			}
		}
		fmt.Printf("SSH key imported into entry %q\n", entryPath)

	case "export":
		cmdSSHExport(obj, subArgs)

	case "scan":
		uuid := ""
		if len(subArgs) > 0 {
			uuid = subArgs[0]
		}
		result := obj.Call(iface+".SshScanDatabase", 0, uuid)
		if result.Err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: failed to scan database: %v\n", result.Err)
			os.Exit(1)
		}
		var entries []map[string]dbus.Variant
		if err := result.Store(&entries); err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: unexpected response: %v\n", err)
			os.Exit(1)
		}
		if len(entries) == 0 {
			fmt.Println("No SSH key entries found")
			return
		}
		fmt.Printf("%-36s %-20s %-15s %-50s %s\n", "Entry UUID", "Title", "Type", "Fingerprint", "Database")
		for _, e := range entries {
			fmt.Printf("%-36s %-20s %-15s %-50s %s\n",
				getVariantString(e["uuid"]),
				getVariantString(e["title"]),
				getVariantString(e["type"]),
				getVariantString(e["fingerprint"]),
				getVariantString(e["db_name"]))
		}

	case "show":
		if len(subArgs) < 1 {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh show: missing fingerprint")
			os.Exit(1)
		}
		fingerprint := subArgs[0]
		result := obj.Call(iface+".SshListKeys", 0, "")
		if result.Err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: failed to list SSH keys: %v\n", result.Err)
			os.Exit(1)
		}
		var keys []map[string]dbus.Variant
		if err := result.Store(&keys); err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: unexpected response: %v\n", err)
			os.Exit(1)
		}
		var found *map[string]dbus.Variant
		for i := range keys {
			if getVariantString(keys[i]["fingerprint"]) == fingerprint {
				found = &keys[i]
				break
			}
		}
		if found == nil {
			fmt.Fprintf(os.Stderr, "kpxcctl: no loaded key with fingerprint %s\n", fingerprint)
			os.Exit(1)
		}
		fmt.Printf("Fingerprint: %s\n", getVariantString((*found)["fingerprint"]))
		fmt.Printf("Type:        %s\n", getVariantString((*found)["type"]))
		fmt.Printf("Comment:     %s\n", getVariantString((*found)["comment"]))
		fmt.Printf("Database:    %s\n", getVariantString((*found)["db_uuid"]))
		fmt.Printf("Entry:       %s\n", getVariantString((*found)["entry_path"]))

	case "diag":
		result := obj.Call(iface+".SshListKeys", 0, "")
		var keys []map[string]dbus.Variant
		if result.Err == nil {
			_ = result.Store(&keys)
		}
		cfg, err := config.Load("")
		mode := "unknown"
		if err == nil {
			mode = cfg.Daemon.SSHMode
		}
		socketPath := os.Getenv("SSH_AUTH_SOCK")
		if socketPath == "" && err == nil {
			socketPath = os.ExpandEnv(cfg.Daemon.SSHSocketPath)
		}
		fmt.Printf("SSH Agent Mode:   %s\n", mode)
		fmt.Printf("SSH_AUTH_SOCK:    %s\n", socketPath)
		fmt.Printf("Loaded Keys:      %d\n", len(keys))
		for _, k := range keys {
			fmt.Printf("  %-15s %s (%s)\n",
				getVariantString(k["type"]),
				getVariantString(k["fingerprint"]),
				getVariantString(k["comment"]))
		}

	default:
		fmt.Fprintf(os.Stderr, "kpxcctl ssh: unknown subcommand: %s\n", subcmd)
		os.Exit(1)
	}
}

// cmdSSHImportMenu scans ~/.ssh and offers a menu of importable keys.
func cmdSSHImportMenu(obj dbus.BusObject, args []string) {
	uuid := ""
	if len(args) > 0 {
		uuid = args[0]
	}
	if uuid == "" {
		// Default to the only unlocked database, if exactly one.
		dbs := listDatabases(obj)
		if len(dbs) == 1 {
			uuid = getVariantString(dbs[0]["uuid"])
		} else if len(dbs) > 1 {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh import: multiple databases unlocked; pass the uuid")
			os.Exit(1)
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "kpxcctl ssh import: cannot resolve home:", err)
		os.Exit(1)
	}
	files, err := scanSSHDir(filepath.Join(home, ".ssh"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "kpxcctl ssh import: cannot read ~/.ssh:", err)
		os.Exit(1)
	}

	// Fingerprints already stored in the target database are skipped.
	existing := map[string]bool{}
	scan := obj.Call(iface+".SshScanDatabase", 0, uuid)
	if scan.Err == nil {
		var entries []map[string]dbus.Variant
		if scan.Store(&entries) == nil {
			for _, e := range entries {
				existing[getVariantString(e["fingerprint"])] = true
			}
		}
	}

	type candidate struct {
		path      string
		key       *sshagent.Key
		data      []byte
		encrypted bool
	}
	var candidates []candidate
	var skipped int
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		key, err := sshagent.ParsePrivateKey(data, "")
		if err != nil {
			skipped++
			continue
		}
		if key == nil {
			skipped++
			continue
		}
		// M7: sk- is a filename prefix, not a substring of the full path.
		if strings.HasPrefix(filepath.Base(f), "sk-") {
			fmt.Printf("  skip %s: security-key (sk-*) keys are not supported\n", filepath.Base(f))
			skipped++
			continue
		}
		if existing[key.Fingerprint()] {
			fmt.Printf("  skip %s: already in the database (%s)\n", filepath.Base(f), key.Fingerprint())
			skipped++
			continue
		}
		// B7: an encrypted key parses to a public-only key (Signer == nil);
		// keep it as a candidate and prompt for the passphrase only if selected.
		candidates = append(candidates, candidate{path: f, key: key, data: data, encrypted: key.Signer == nil})
	}
	if len(candidates) == 0 {
		fmt.Printf("no importable keys in ~/.ssh (%d skipped)\n", skipped)
		return
	}
	if !stdinIsInteractive() {
		fmt.Fprintln(os.Stderr, "kpxcctl ssh import: stdin is not interactive; use: kpxcctl ssh import <uuid> <entry> <file>")
		os.Exit(1)
	}

	items := make([]string, len(candidates))
	for i, c := range candidates {
		enc := ""
		if c.encrypted {
			enc = "  (encrypted)"
		}
		items[i] = fmt.Sprintf("%s  %s  %s%s", filepath.Base(c.path), c.key.Format, c.key.Fingerprint(), enc)
	}
	fmt.Printf("%d keys found in ~/.ssh:\n", len(candidates))
	picked, err := selectFromMenu(os.Stdin, "import which? numbers (comma-separated), 'a' for all, enter to cancel: ", items)
	if err != nil || len(picked) == 0 {
		fmt.Println("nothing selected — nothing imported")
		return
	}

	fmt.Println("Keys are stored unencrypted inside the encrypted vault; the vault master password protects them.")
	imported, failed := 0, 0
	for _, idx := range picked {
		c := candidates[idx]
		title := fmt.Sprintf("%s (%s)", filepath.Base(c.path), shortFP(c.key.Fingerprint()))
		passphrase := ""
		if c.encrypted {
			passphrase = readSecretPrompt(fmt.Sprintf("Passphrase for %s: ", filepath.Base(c.path)))
		}
		call := obj.Call(iface+".SshImportKey", 0, uuid, title, c.data, passphrase)
		if call.Err != nil {
			fmt.Fprintf(os.Stderr, "  fail %s: %v\n", title, call.Err)
			failed++
			continue
		}
		fmt.Printf("  imported %s\n", title)
		imported++
	}
	fmt.Printf("\n%d imported, %d failed\n", imported, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

func shortFP(fp string) string {
	if len(fp) > 19 {
		return fp[:19]
	}
	return fp
}

func listDatabases(obj dbus.BusObject) []map[string]dbus.Variant {
	call := obj.Call(iface+".ListDatabases", 0)
	if call.Err != nil {
		return nil
	}
	var dbs []map[string]dbus.Variant
	if call.Store(&dbs) != nil {
		return nil
	}
	unlocked := dbs[:0]
	for _, db := range dbs {
		if !getVariantBool(db["locked"]) {
			unlocked = append(unlocked, db)
		}
	}
	return unlocked
}

// cmdSSHAutoload shows a menu of the database's keys and toggles auto-load.
func cmdSSHAutoload(obj dbus.BusObject, args []string) {
	// Explicit form: autoload <uuid> <entry> on|off [--override-deny]
	if len(args) >= 3 {
		uuid, entryRef, state := args[0], args[1], args[2]
		on := state == "on"
		if state != "on" && state != "off" {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh autoload: state must be on|off")
			os.Exit(1)
		}
		override := false
		for _, a := range args[3:] {
			if a == "--override-deny" {
				override = true
			}
		}
		call := obj.Call(iface+".SshSetAutoload", 0, uuid, entryRef, on, override)
		if call.Err != nil {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh autoload:", call.Err)
			os.Exit(1)
		}
		fmt.Printf("autoload %s for %s (applies at next unlock; use `ssh add` to load now)\n", state, entryRef)
		return
	}

	uuid := ""
	if len(args) > 0 {
		uuid = args[0]
	}
	if uuid == "" {
		dbs := listDatabases(obj)
		if len(dbs) == 1 {
			uuid = getVariantString(dbs[0]["uuid"])
		} else if len(dbs) > 1 {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh autoload: multiple databases unlocked; pass the uuid")
			os.Exit(1)
		}
	}
	if !stdinIsInteractive() {
		fmt.Fprintln(os.Stderr, "kpxcctl ssh autoload: stdin is not interactive; use: kpxcctl ssh autoload <uuid> <entry> on|off")
		os.Exit(1)
	}

	call := obj.Call(iface+".SshScanDatabase", 0, uuid)
	if call.Err != nil {
		fmt.Fprintln(os.Stderr, "kpxcctl ssh autoload:", call.Err)
		os.Exit(1)
	}
	var entries []map[string]dbus.Variant
	if call.Store(&entries) != nil || len(entries) == 0 {
		fmt.Println("no keys found")
		return
	}
	items := make([]string, len(entries))
	for i, e := range entries {
		mark := " "
		if getVariantBool(e["autoload"]) {
			mark = "x"
		}
		denied := ""
		if getVariantBool(e["denied"]) {
			denied = " (KeeAgent-denied)"
		}
		items[i] = fmt.Sprintf("[%s] %s  %s  %s%s", mark, getVariantString(e["title"]),
			getVariantString(e["fingerprint"]), getVariantString(e["source"]), denied)
	}
	fmt.Println("auto-load at unlock:")
	picked, err := selectFromMenu(os.Stdin, "toggle which? numbers (comma-separated), enter for none: ", items)
	if err != nil {
		fmt.Fprintln(os.Stderr, "kpxcctl ssh autoload:", err)
		os.Exit(1)
	}
	if len(picked) == 0 {
		fmt.Println("nothing changed")
		return
	}
	for _, idx := range picked {
		e := entries[idx]
		on := !getVariantBool(e["autoload"])
		override := getVariantBool(e["denied"]) && on
		set := obj.Call(iface+".SshSetAutoload", 0, uuid, getVariantString(e["uuid"]), on, override)
		if set.Err != nil {
			fmt.Fprintf(os.Stderr, "  fail %s: %v\n", getVariantString(e["title"]), set.Err)
			continue
		}
		fmt.Printf("  %s -> autoload=%v\n", getVariantString(e["title"]), on)
	}
	fmt.Println("applies at next unlock; use `kpxcctl ssh add` to load a key now")
}

// cmdSSHExport exports a stored key to OpenSSH format. The daemon gates the
// call behind polkit auth_self. Output is O_EXCL|O_NOFOLLOW 0600, encrypted
// with a passphrase unless --no-passphrase (which requires typed consent).
func cmdSSHExport(obj dbus.BusObject, args []string) {
	force, noPassphrase := false, false
	var pos []string
	for _, a := range args {
		switch a {
		case "--force":
			force = true
		case "--no-passphrase":
			noPassphrase = true
		default:
			pos = append(pos, a)
		}
	}

	uuid, entryRef := "", ""
	switch len(pos) {
	case 0:
		// menu form
	case 2:
		uuid, entryRef = pos[0], pos[1]
	case 3:
		uuid, entryRef = pos[0], pos[1]
	default:
		fmt.Fprintln(os.Stderr, "kpxcctl ssh export: usage: export [uuid] | export <uuid> <entry> <file> [--force] [--no-passphrase]")
		os.Exit(1)
	}

	if uuid == "" {
		dbs := listDatabases(obj)
		if len(dbs) == 1 {
			uuid = getVariantString(dbs[0]["uuid"])
		} else if len(dbs) > 1 {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh export: multiple databases unlocked; pass the uuid")
			os.Exit(1)
		}
	}

	outFile := ""
	if len(pos) == 3 {
		outFile = pos[2]
	}
	if len(pos) == 0 {
		if !stdinIsInteractive() {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh export: stdin is not interactive; use: kpxcctl ssh export <uuid> <entry> <file>")
			os.Exit(1)
		}
		scan := obj.Call(iface+".SshScanDatabase", 0, uuid)
		if scan.Err != nil {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh export:", scan.Err)
			os.Exit(1)
		}
		var entries []map[string]dbus.Variant
		if scan.Store(&entries) != nil || len(entries) == 0 {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh export: no keys found")
			os.Exit(1)
		}
		items := make([]string, len(entries))
		for i, e := range entries {
			items[i] = fmt.Sprintf("%s  %s  %s", getVariantString(e["title"]), getVariantString(e["type"]), getVariantString(e["fingerprint"]))
		}
		picked, err := selectFromMenu(os.Stdin, "export which? number, enter to cancel: ", items)
		if err != nil || len(picked) == 0 {
			fmt.Println("nothing selected")
			return
		}
		entryRef = getVariantString(entries[picked[0]]["uuid"])
		fmt.Print("output file: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		outFile = strings.TrimSpace(line)
		if outFile == "" || outFile == "-" || outFile == "/dev/stdout" {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh export: refusing to write to stdout")
			os.Exit(1)
		}
	}
	if outFile == "" || outFile == "-" || outFile == "/dev/stdout" {
		fmt.Fprintln(os.Stderr, "kpxcctl ssh export: refusing to write to stdout; give a file path")
		os.Exit(1)
	}

	// B8c: validate the output path before triggering the polkit prompt.
	if outFile != "" {
		if fi, serr := os.Lstat(outFile); serr == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				fmt.Fprintln(os.Stderr, "kpxcctl ssh export: refusing to write through a symlink")
				os.Exit(1)
			}
			if !force && fi.Mode().IsRegular() {
				fmt.Fprintln(os.Stderr, "kpxcctl ssh export: file exists (use --force to overwrite)")
				os.Exit(1)
			}
		}
	}

	call := obj.Call(iface+".SshExportKey", 0, uuid, entryRef)
	if call.Err != nil {
		fmt.Fprintln(os.Stderr, "kpxcctl ssh export:", call.Err)
		os.Exit(1)
	}
	var pemBytes []byte
	if call.Store(&pemBytes) != nil {
		fmt.Fprintln(os.Stderr, "kpxcctl ssh export: unexpected response")
		os.Exit(1)
	}

	// Encrypt by default. An empty passphrase is an error (it would silently
	// produce an unencrypted key); --no-passphrase requires typed consent.
	out := pemBytes
	if !noPassphrase {
		p1 := readSecretPrompt("Passphrase for exported key: ")
		p2 := readSecretPrompt("Repeat passphrase: ")
		if p1 != p2 {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh export: passphrases do not match")
			os.Exit(1)
		}
		if p1 == "" {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh export: empty passphrase is not allowed; use --no-passphrase with explicit consent")
			os.Exit(1)
		}
		key, err := sshagent.ParsePrivateKey(pemBytes, "")
		if err != nil {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh export: cannot re-encrypt:", err)
			os.Exit(1)
		}
		block, err := ssh.MarshalPrivateKeyWithPassphrase(key.PrivateKey, "", []byte(p1))
		if err != nil {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh export: encrypt:", err)
			os.Exit(1)
		}
		out = pem.EncodeToMemory(block)
	} else if stdinIsInteractive() {
		fmt.Print("Export an UNENCRYPTED private key? Type \"yes\": ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			fmt.Fprintln(os.Stderr, "kpxcctl ssh export: not confirmed")
			os.Exit(1)
		}
	}
	if noPassphrase {
		fmt.Fprintln(os.Stderr, "WARNING: exporting an UNENCRYPTED private key; the file is 0600 but anyone who can read it can use the key.")
	}

	if err := writeExportFile(outFile, out); err != nil {
		fmt.Fprintln(os.Stderr, "kpxcctl ssh export:", err)
		os.Exit(1)
	}
	fmt.Printf("exported %s to %s (mode 0600)\n", entryRef, outFile)
}

// writeExportFile writes a private key to outFile as a fresh 0600 file
// renamed over the target: never O_TRUNC (would keep the old mode), never
// through a symlink.
func writeExportFile(outFile string, data []byte) error {
	if fi, err := os.Lstat(outFile); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write through a symlink")
	}
	dir := filepath.Dir(outFile)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(outFile)+".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, outFile)
}

// cmdPasskey handles passkey subcommands: list, create, remove, import.
// Assertions happen in browsers; the daemon CTAP surface handles them.
func cmdPasskey(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "kpxcctl passkey: missing subcommand (list, create, remove, import)")
		os.Exit(1)
	}

	obj, conn, err := connectDBus()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()

	switch args[0] {
	case "list":
		passkeyList(obj)
	case "create":
		if len(args) < 4 {
			fmt.Fprintln(os.Stderr, "kpxcctl passkey create: usage: passkey create <uuid> <rpID> <username> [displayName]")
			os.Exit(1)
		}
		display := args[3]
		if len(args) > 4 {
			display = args[4]
		}
		call := obj.Call(iface+".CreatePasskey", 0, args[1], args[2], args[2], args[3], display, []int32{-7})
		if call.Err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl passkey create: %v\n", call.Err)
			os.Exit(1)
		}
		var out map[string]dbus.Variant
		if err := call.Store(&out); err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl passkey create: unexpected response: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("created passkey %s for %s (%s)\n",
			getVariantString(out["credentialID"]), getVariantString(out["rpID"]), getVariantString(out["username"]))

	case "remove":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "kpxcctl passkey remove: usage: passkey remove <credentialID>")
			os.Exit(1)
		}
		call := obj.Call(iface+".RemovePasskey", 0, args[1])
		if call.Err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl passkey remove: %v\n", call.Err)
			os.Exit(1)
		}
		fmt.Printf("removed passkey %s\n", args[1])

	case "import":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "kpxcctl passkey import: usage: passkey import <uuid> <bitwarden-export.json> [--dry-run]")
			os.Exit(1)
		}
		rpFilter, credFilter, importAll := "", "", false
		for _, flag := range args[3:] {
			switch {
			case flag == "--all":
				importAll = true
			case flag == "--dry-run":
				// consumed inside passkeyImport via os.Args
			case strings.HasPrefix(flag, "--rp="):
				rpFilter = strings.TrimPrefix(flag, "--rp=")
			case strings.HasPrefix(flag, "--cred="):
				credFilter = strings.TrimPrefix(flag, "--cred=")
			default:
				fmt.Fprintf(os.Stderr, "kpxcctl passkey import: unknown flag %q (use --all, --rp=<rpID>, --cred=<credentialID>)\n", flag)
				os.Exit(1)
			}
		}
		passkeyImport(obj, args[1], args[2], rpFilter, credFilter, importAll)

	default:
		fmt.Fprintf(os.Stderr, "kpxcctl passkey: unknown subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

// passkeyList prints metadata for every stored passkey.
func passkeyList(obj dbus.BusObject) {
	call := obj.Call(iface+".ListPasskeys", 0)
	if call.Err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl passkey list: %v\n", call.Err)
		os.Exit(1)
	}
	var rows []map[string]dbus.Variant
	if err := call.Store(&rows); err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl passkey list: unexpected response: %v\n", err)
		os.Exit(1)
	}
	if len(rows) == 0 {
		fmt.Println("no passkeys stored")
		return
	}
	for _, row := range rows {
		fmt.Printf("%s  %s@%s  cred=%s  count=%d  db=%s\n",
			getVariantString(row["rpID"]),
			getVariantString(row["username"]),
			getVariantString(row["rpName"]),
			getVariantString(row["credentialID"]),
			getVariantUint32(row["signCount"]),
			getVariantString(row["database"]))
	}
}

// stdinIsInteractive reports whether standard input is a terminal, so
// the interactive credential picker only runs for humans.
func stdinIsInteractive() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// candidate is one importable passkey from a Bitwarden export.
type candidate struct {
	entry fido2.ImportPasskeyInput
	cred  bitwardenFido2Credential
}

// passkeyImport ingests a decrypted Bitwarden JSON vault export. Secrets
// in the file are hot: print a reminder, never echo key material. With
// no filter the candidates are listed and selected interactively; --all,
// --rp=<rpID> and --cred=<credentialID> select non-interactively.
func passkeyImport(obj dbus.BusObject, uuid, path, rpFilter, credFilter string, importAll bool) {
	dryRun := false
	for _, arg := range os.Args {
		if arg == "--dry-run" {
			dryRun = true
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl passkey import: %v\n", err)
		os.Exit(1)
	}

	var export bitwardenExport
	if err := json.Unmarshal(data, &export); err != nil {
		fmt.Fprintf(os.Stderr, "kpxcctl passkey import: not a valid Bitwarden JSON export: %v\n", err)
		os.Exit(1)
	}

	var candidates []candidate
	skipped := 0
	for _, item := range export.Items {
		if item.Login == nil {
			continue
		}
		for _, cred := range item.Login.Fido2Credentials {
			entry, err := parseBitwardenCredential(cred)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  skip %s: %v\n", cred.CredentialID, err)
				skipped++
				continue
			}
			if rpFilter != "" && entry.RPID != rpFilter {
				continue
			}
			if credFilter != "" && entry.CredentialID != credFilter {
				continue
			}
			candidates = append(candidates, candidate{entry: entry, cred: cred})
		}
	}
	if len(candidates) == 0 {
		fmt.Println("no matching passkeys in the export")
		if skipped > 0 {
			fmt.Printf("%d skipped (unsupported or filtered)\n", skipped)
		}
		return
	}

	selected := candidates
	if !importAll && rpFilter == "" && credFilter == "" && !stdinIsInteractive() {
		fmt.Fprintln(os.Stderr, "kpxcctl passkey import: no selection and stdin is not interactive; pass --all, --rp=<rpID> or --cred=<credentialID>")
		os.Exit(1)
	}
	if !importAll && rpFilter == "" && credFilter == "" {
		selected, err = selectCandidates(candidates, os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "kpxcctl passkey import: %v\n", err)
			os.Exit(1)
		}
		if len(selected) == 0 {
			fmt.Println("nothing selected — nothing imported")
			return
		}
	}

	if dryRun {
		for _, c := range selected {
			fmt.Printf("would import %s@%s (cred=%s, count=%d)\n",
				c.entry.Username, c.entry.RPID, c.entry.CredentialID, c.entry.SignCount)
		}
		fmt.Println("dry run — nothing written")
		return
	}

	fmt.Println("Secrets in the export file are live: delete the file after importing.")
	imported, failed := 0, 0
	for _, c := range selected {
		entry := c.entry
		call := obj.Call(iface+".ImportPasskey", 0,
			uuid, entry.RPID, entry.RPName, entry.Username, entry.UserDisplayName,
			entry.CredentialID, entry.UserHandle, entry.PrivateKeyPEM, int32(entry.SignCount))
		if call.Err != nil {
			fmt.Fprintf(os.Stderr, "  fail %s@%s: %v\n", entry.Username, entry.RPID, call.Err)
			failed++
			continue
		}
		fmt.Printf("imported %s@%s (cred=%s)\n", entry.Username, entry.RPID, entry.CredentialID)
		imported++
	}

	fmt.Printf("\n%d imported, %d failed\n", imported, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// selectCandidates prints the numbered candidate list and reads the
// user's pick: a comma-separated list of numbers, or "a"/"all". An empty
// answer selects nothing.
func selectCandidates(candidates []candidate, input io.Reader) ([]candidate, error) {
	fmt.Printf("%d passkeys in the export:\n", len(candidates))
	for i, c := range candidates {
		fmt.Printf("  %d. %s@%s (cred=%s, count=%d)\n",
			i+1, c.entry.Username, c.entry.RPID, c.entry.CredentialID, c.entry.SignCount)
	}
	fmt.Print("import which? numbers (comma-separated), 'a' for all, enter to cancel: ")

	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil && line == "" {
		return nil, fmt.Errorf("read selection: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	if strings.EqualFold(line, "a") || strings.EqualFold(line, "all") {
		return candidates, nil
	}

	var picked []candidate
	for _, field := range strings.Split(line, ",") {
		field = strings.TrimSpace(field)
		n, err := strconv.Atoi(field)
		if err != nil || n < 1 || n > len(candidates) {
			return nil, fmt.Errorf("invalid selection %q", field)
		}
		picked = append(picked, candidates[n-1])
	}
	return picked, nil
}

// bitwardenExport models the decrypted Bitwarden JSON vault export.
type bitwardenExport struct {
	Items []struct {
		Login *struct {
			Fido2Credentials []bitwardenFido2Credential `json:"fido2Credentials"`
		} `json:"login"`
	} `json:"items"`
}

type bitwardenFido2Credential struct {
	CredentialID    string `json:"credentialId"`
	KeyType         string `json:"keyType"`
	KeyAlgorithm    string `json:"keyAlgorithm"`
	KeyCurve        string `json:"keyCurve"`
	KeyValue        string `json:"keyValue"`
	RPID            string `json:"rpId"`
	RPName          string `json:"rpName"`
	UserHandle      string `json:"userHandle"`
	UserName        string `json:"userName"`
	UserDisplayName string `json:"userDisplayName"`
	Counter         string `json:"counter"`
	Discoverable    string `json:"discoverable"`
	CreationDate    string `json:"creationDate"`
}

// parseBitwardenCredential validates one Bitwarden passkey and converts it
// into the kpxcd import shape: base64url IDs, PKCS#8 PEM key, counter.
func parseBitwardenCredential(cred bitwardenFido2Credential) (fido2.ImportPasskeyInput, error) {
	var in fido2.ImportPasskeyInput
	if cred.KeyType != "public-key" || cred.KeyAlgorithm != "ECDSA" || cred.KeyCurve != "P-256" {
		return in, fmt.Errorf("unsupported key type %s/%s/%s (only ECDSA P-256)", cred.KeyType, cred.KeyAlgorithm, cred.KeyCurve)
	}
	if cred.RPID == "" || cred.CredentialID == "" || cred.UserHandle == "" || cred.KeyValue == "" {
		return in, fmt.Errorf("missing required fields")
	}

	// Bitwarden stores DER PKCS#8 as base64url (dashes/underscores,
	// usually unpadded); older exports used standard base64. Decode any
	// of the three shapes; kpxcd stores PEM.
	trimmed := strings.TrimRight(cred.KeyValue, "=")
	der, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil {
		der, err = base64.RawStdEncoding.DecodeString(trimmed)
	}
	if err != nil {
		der, err = base64.StdEncoding.DecodeString(cred.KeyValue)
	}
	if err != nil {
		return in, fmt.Errorf("keyValue is not base64: %w", err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	// Credential IDs: sites like GitHub and Amazon issue UUID-shaped
	// credential IDs whose wire form is the UUID's 16 raw bytes (the
	// dashes are display formatting). Hex-decode those; everything else
	// is base64url (padding varies) and normalizes to kpxcd's canonical
	// unpadded form.
	credID, err := credentialIDForVault(cred.CredentialID)
	if err != nil {
		return in, fmt.Errorf("credentialId is not base64url: %w", err)
	}
	handle, err := normalizeBase64URL(cred.UserHandle)
	if err != nil {
		return in, fmt.Errorf("userHandle is not base64: %w", err)
	}

	count := uint32(0)
	if cred.Counter != "" {
		parsed, err := strconv.ParseUint(cred.Counter, 10, 32)
		if err != nil {
			return in, fmt.Errorf("counter is not a number: %w", err)
		}
		count = uint32(parsed)
	}

	display := cred.UserDisplayName
	if display == "" {
		display = cred.UserName
	}

	return fido2.ImportPasskeyInput{
		RPID:            cred.RPID,
		RPName:          cred.RPName,
		Username:        cred.UserName,
		UserDisplayName: display,
		CredentialID:    credID,
		UserHandle:      handle,
		PrivateKeyPEM:   pemKey,
		SignCount:       count,
	}, nil
}

var uuidShape = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// credentialIDForVault normalizes an exported credential ID into the
// unpadded base64url string of its wire bytes. UUID-shaped IDs (GitHub,
// Amazon, ...) hex-decode to 16 bytes; everything else is treated as
// base64 of the raw bytes.
func credentialIDForVault(id string) (string, error) {
	if uuidShape.MatchString(id) {
		raw, err := hex.DecodeString(strings.ReplaceAll(strings.ToLower(id), "-", ""))
		if err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(raw), nil
	}
	return normalizeBase64URL(id)
}

// normalizeBase64URL decodes std-or-url, padded-or-not base64 and
// re-encodes kpxcd's canonical unpadded base64url form.
func normalizeBase64URL(s string) (string, error) {
	trimmed := strings.TrimRight(s, "=")
	decoded, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(trimmed)
		if err != nil {
			decoded, err = base64.StdEncoding.DecodeString(s)
			if err != nil {
				return "", err
			}
		}
	}
	return base64.RawURLEncoding.EncodeToString(decoded), nil
}

// getVariantUint32 extracts a uint32 from a Variant, or 0.
func getVariantUint32(v dbus.Variant) uint32 {
	n, _ := v.Value().(uint32)
	return n
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
