# Sourced from the user's interactive Bash rc by the Guardian installer.
_omarchy_guardian_help_requested() {
    local arg
    for arg in "$@"; do
        [[ $arg == --help || $arg == -h ]] && return 0
    done
    return 1
}

omarchy() {
    if [[ ${1-} == theme && ${2-} == install ]]; then
        if _omarchy_guardian_help_requested "$@"; then
            command /usr/share/omarchy/bin/omarchy "$@"
            return
        fi
        shift 2
        /usr/lib/omarchy-guardian/guardian-theme install "$@"
    elif [[ ${1-} == theme && ${2-} == update ]]; then
        if _omarchy_guardian_help_requested "$@"; then
            command /usr/share/omarchy/bin/omarchy "$@"
            return
        fi
        shift 2
        /usr/lib/omarchy-guardian/guardian-theme update "$@"
    else
        command /usr/share/omarchy/bin/omarchy "$@"
    fi
}

omarchy-theme-install() {
    if _omarchy_guardian_help_requested "$@"; then
        command /usr/share/omarchy/bin/omarchy theme install --help
        return
    fi
    /usr/lib/omarchy-guardian/guardian-theme install "$@"
}

omarchy-theme-update() {
    if _omarchy_guardian_help_requested "$@"; then
        command /usr/share/omarchy/bin/omarchy theme update --help
        return
    fi
    /usr/lib/omarchy-guardian/guardian-theme update "$@"
}
