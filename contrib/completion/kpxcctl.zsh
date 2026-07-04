#compdef kpxcctl
# Zsh completion for kpxcctl — KeePassXC Daemon CLI client
# Install: copy to /usr/share/zsh/site-functions/_kpxcctl or ~/.zfunctions/_kpxcctl

_kpxcctl() {
    local -a _kpxcctl_cmds
    _kpxcctl_cmds=(
        'unlock:Unlock a KeePass database'
        'lock:Lock a database'
        'list:List unlocked databases'
        'get:Get entry fields'
        'ssh:Manage SSH keys'
        'passkey:Reserved passkey commands'
        'ping:Check if daemon is alive'
        'help:Show help message'
    )

    local -a _ssh_subcmds
    _ssh_subcmds=(
        'list:List SSH keys in the agent'
        'add:Add an SSH key to the agent'
        'remove:Remove an SSH key from the agent'
    )

    local -a _passkey_subcmds
    _passkey_subcmds=(
        'create:Disabled: passkey API is not implemented'
        'assert:Disabled: passkey API is not implemented'
    )

    _arguments -C \
        '1: :->cmd' \
        '2: :->subcmd' \
        '3: :->arg1' \
        '4: :->arg2' \
        '5: :->arg3' \
        && return 0

    case $state in
        cmd)
            _describe 'command' _kpxcctl_cmds
            ;;
        subcmd)
            case $words[2] in
                unlock)
                    _arguments '1:database file:_files -g "*.kdbx"' \
                        && return 0
                    ;;
                lock)
                    _arguments '1: :->locktarget' && return 0
                    case $state in
                        locktarget)
                            local -a _lock_targets
                            _lock_targets=('all:Lock all databases')
                            # Try to get UUIDs from kpxcctl list
                            local _uuids
                            _uuids=$(kpxcctl list 2>/dev/null | tail -n +3 | awk '{print $1}')
                            if [[ -n $_uuids ]]; then
                                _lock_targets+=("${(@s: :)${(@f)${_uuids}}}")
                            fi
                            _describe 'database' _lock_targets
                            ;;
                    esac
                    ;;
                get)
                    _arguments '1:database UUID:_kpxcctl_uuids' \
                               '2:entry path:' \
                        && return 0
                    ;;
                ssh)
                    _describe 'ssh subcommand' _ssh_subcmds
                    ;;
                passkey)
                    _describe 'passkey subcommand' _passkey_subcmds
                    ;;
            esac
            ;;
        arg1)
            case $words[2] in
                unlock)
                    _files -g "*.kdbx"
                    ;;
                ssh)
                    case $words[3] in
                        add)
                            _arguments '1:database UUID:_kpxcctl_uuids' && return 0
                            ;;
                    esac
                    ;;
                passkey)
                    case $words[3] in
                        create)
                            _arguments '1:database UUID:_kpxcctl_uuids' && return 0
                            ;;
                    esac
                    ;;
            esac
            ;;
        arg2)
            case $words[2] in
                ssh)
                    case $words[3] in
                        add)
                            _message 'entry path'
                            ;;
                        remove)
                            _message 'SSH key fingerprint'
                            ;;
                    esac
                    ;;
                passkey)
                    case $words[3] in
                        create)
                            _arguments '1:relying party ID:(github.com gitlab.com google.com)' && return 0
                            ;;
                        assert)
                            _arguments '1:relying party ID:(github.com gitlab.com google.com)' && return 0
                            ;;
                    esac
                    ;;
            esac
            ;;
        arg3)
            case $words[2] in
                passkey)
                    case $words[3] in
                        create)
                            _message 'username'
                            ;;
                        assert)
                            _message 'credential ID'
                            ;;
                    esac
                    ;;
            esac
            ;;
    esac
}

# Helper: provide UUIDs from currently unlocked databases
_kpxcctl_uuids() {
    local -a _uuids
    local _output
    _output=$(kpxcctl list 2>/dev/null | tail -n +3 | awk '{print $1}')
    if [[ -n $_output ]]; then
        while IFS= read -r line; do
            [[ -n $line ]] && _uuids+=("$line")
        done <<< "$_output"
        _describe 'database UUID' _uuids
    else
        _message 'no unlocked databases'
    fi
}

_kpxcctl "$@"
