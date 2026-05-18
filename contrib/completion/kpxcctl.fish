# Fish shell completion for kpxcctl — KeePassXC Daemon CLI client
# Install: copy to ~/.local/share/fish/completions/kpxcctl.fish

complete -c kpxcctl -n "__fish_use_subcommand" -a unlock -d "Unlock a KeePass database"
complete -c kpxcctl -n "__fish_use_subcommand" -a lock -d "Lock a database"
complete -c kpxcctl -n "__fish_use_subcommand" -a list -d "List unlocked databases"
complete -c kpxcctl -n "__fish_use_subcommand" -a get -d "Get entry fields"
complete -c kpxcctl -n "__fish_use_subcommand" -a ssh -d "Manage SSH keys"
complete -c kpxcctl -n "__fish_use_subcommand" -a passkey -d "Manage passkeys"
complete -c kpxcctl -n "__fish_use_subcommand" -a ping -d "Check if daemon is alive"
complete -c kpxcctl -n "__fish_use_subcommand" -a help -d "Show help message"

# unlock: expects a .kdbx file path
complete -c kpxcctl -n "__fish_seen_subcommand_from unlock" -f -a "(__fish_complete_suffix .kdbx)" -d "Database file"

# lock: accepts "all" or a UUID
complete -c kpxcctl -n "__fish_seen_subcommand_from lock" -a all -d "Lock all databases"
complete -c kpxcctl -n "__fish_seen_subcommand_from lock; and not __fish_seen_subcommand_from unlock list get ssh passkey ping help" -a "(kpxcctl list 2>/dev/null | string match -r '^[0-9a-f-]{36}' || true)" -d "Database UUID"

# get: expects <uuid> <entry-path>
complete -c kpxcctl -n "__fish_seen_subcommand_from get; and count (commandline -opc) -le 3" -a "(kpxcctl list 2>/dev/null | string match -r '^[0-9a-f-]{36}' || true)" -d "Database UUID"
complete -c kpxcctl -n "__fish_seen_subcommand_from get; and count (commandline -opc) -eq 4" -d "Entry path (e.g. /General/example.com)"

# ssh subcommands
complete -c kpxcctl -n "__fish_seen_subcommand_from ssh; and not __fish_seen_subcommand_from list add remove" -a list -d "List SSH keys in the agent"
complete -c kpxcctl -n "__fish_seen_subcommand_from ssh; and not __fish_seen_subcommand_from list add remove" -a add -d "Add an SSH key to the agent"
complete -c kpxcctl -n "__fish_seen_subcommand_from ssh; and not __fish_seen_subcommand_from list add remove" -a remove -d "Remove an SSH key from the agent"

# ssh add: expects <uuid> <entry-path>
complete -c kpxcctl -n "__fish_seen_subcommand_from ssh; and __fish_seen_subcommand_from add; and count (commandline -opc) -le 4" -a "(kpxcctl list 2>/dev/null | string match -r '^[0-9a-f-]{36}' || true)" -d "Database UUID"
complete -c kpxcctl -n "__fish_seen_subcommand_from ssh; and __fish_seen_subcommand_from add; and count (commandline -opc) -eq 5" -d "Entry path"

# ssh remove: expects <fingerprint>
complete -c kpxcctl -n "__fish_seen_subcommand_from ssh; and __fish_seen_subcommand_from remove" -d "SSH key fingerprint"

# passkey subcommands
complete -c kpxcctl -n "__fish_seen_subcommand_from passkey; and not __fish_seen_subcommand_from create assert" -a create -d "Create a new passkey"
complete -c kpxcctl -n "__fish_seen_subcommand_from passkey; and not __fish_seen_subcommand_from create assert" -a assert -d "Assert a passkey"

# passkey create: expects <uuid> <rpID> <username>
complete -c kpxcctl -n "__fish_seen_subcommand_from passkey; and __fish_seen_subcommand_from create; and count (commandline -opc) -le 4" -a "(kpxcctl list 2>/dev/null | string match -r '^[0-9a-f-]{36}' || true)" -d "Database UUID"
complete -c kpxcctl -n "__fish_seen_subcommand_from passkey; and __fish_seen_subcommand_from create; and count (commandline -opc) -eq 5" -a "github.com gitlab.com google.com" -d "Relying party ID"
complete -c kpxcctl -n "__fish_seen_subcommand_from passkey; and __fish_seen_subcommand_from create; and count (commandline -opc) -eq 6" -d "Username"

# passkey assert: expects <rpID> <credentialID>
complete -c kpxcctl -n "__fish_seen_subcommand_from passkey; and __fish_seen_subcommand_from assert; and count (commandline -opc) -le 4" -a "github.com gitlab.com google.com" -d "Relying party ID"
complete -c kpxcctl -n "__fish_seen_subcommand_from passkey; and __fish_seen_subcommand_from assert; and count (commandline -opc) -eq 5" -d "Credential ID"
