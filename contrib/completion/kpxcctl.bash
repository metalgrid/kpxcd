# Bash completion for kpxcctl — KeePassXC Daemon CLI client
# Install: copy to /usr/share/bash-completion/completions/kpxcctl or ~/.local/share/bash-completion/completions/kpxcctl

_kpxcctl() {
    local cur prev words cword
    _init_completion || return

    local cmd="${words[1]}"
    local subcmd="${words[2]}"

    case "$cword" in
        1)
            # Complete top-level subcommands
            COMPREPLY=( $(compgen -W 'unlock lock list get ssh passkey ping help' -- "$cur") )
            return
            ;;
        2)
            case "$cmd" in
                unlock)
                    # Suggest .kdbx files in current directory and home
                    COMPREPLY=( $(compgen -G '*.kdbx' -W "$HOME" -- "$cur") )
                    return
                    ;;
                lock)
                    # Suggest "all" or try to list database UUIDs
                    COMPREPLY=( $(compgen -W 'all' -- "$cur") )
                    return
                    ;;
                ssh)
                    COMPREPLY=( $(compgen -W 'list add remove' -- "$cur") )
                    return
                    ;;
                passkey)
                    COMPREPLY=( $(compgen -W 'create assert' -- "$cur") )
                    return
                    ;;
                get|list|ping|help)
                    return
                    ;;
            esac
            ;;
        3)
            case "$cmd" in
                ssh)
                    case "$subcmd" in
                        add)
                            # Suggest UUIDs from kpxcctl list
                            _kpxcctl_list_uuids
                            return
                            ;;
                    esac
                    ;;
                passkey)
                    case "$subcmd" in
                        create)
                            _kpxcctl_list_uuids
                            return
                            ;;
                    esac
                    ;;
            esac
            ;;
        4)
            case "$cmd" in
                get)
                    # Suggest common entry paths
                    _kpxcctl_list_entries "$prev"
                    return
                    ;;
                ssh)
                    case "$subcmd" in
                        add)
                            # Suggest entry paths
                            _kpxcctl_list_entries "$prev"
                            return
                            ;;
                    esac
                    ;;
                passkey)
                    case "$subcmd" in
                        create)
                            # Suggest rpID (e.g., github.com, gitlab.com)
                            COMPREPLY=( $(compgen -W 'github.com gitlab.com google.com' -- "$cur") )
                            return
                            ;;
                    esac
                    ;;
            esac
            ;;
        5)
            case "$cmd" in
                passkey)
                    case "$subcmd" in
                        create)
                            # Suggest username
                            return
                            ;;
                    esac
                    ;;
            esac
            ;;
    esac

    # General file completion as fallback
    _filedir
}

# Helper: retrieve UUIDs from currently unlocked databases
_kpxcctl_list_uuids() {
    local uuids
    uuids=$(kpxcctl list 2>/dev/null | tail -n +3 | awk '{print $1}')
    if [[ -n "$uuids" ]]; then
        COMPREPLY=( $(compgen -W "$uuids" -- "$cur") )
    fi
}

# Helper: suggest entry paths given a database UUID
_kpxcctl_list_entries() {
    local uuid="$1"
    if [[ -n "$uuid" ]]; then
        # This would ideally call a kpxcctl subcommand to list entries;
        # for now, fall back to path completion.
        _filedir
    fi
}

complete -F _kpxcctl kpxcctl
