//go:build linux

// Package main implements the kpxcctl CLI client for the kpxcd daemon.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/godbus/dbus/v5"
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
  unlock <path>              Unlock a KeePass database
  lock [uuid|name]           Lock a database (or all)
  list                       List unlocked databases
  get <uuid> <entry-path>    Get entry fields (password, username, TOTP)
  ssh list                   List SSH keys in the agent
  ssh add <uuid> <entry>    Add an SSH key to the agent
  ssh remove <fingerprint>  Remove an SSH key from the agent
  passkey create <uuid> <rpID> <username>  Create a new passkey
  passkey assert <rpID> <credID>            Assert a passkey
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

// cmdUnlock unlocks a database.
func cmdUnlock(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "kpxcctl unlock: missing database path")
		os.Exit(1)
	}

	path := args[0]
	obj, conn, err := connectDBus()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()

	// Read password from stdin if not provided.
	var password string
	fmt.Print("Database password: ")
	fmt.Scanln(&password)

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