#!/bin/sh
# Activates the Guardian pacman hook and the Bash theme interceptor after the
# omarchy-guardian package is installed. Installing the package alone changes
# no system behaviour.
set -eu

HOOK_SOURCE=/usr/share/omarchy-guardian/omarchy-guardian.hook
HOOK_TARGET=/etc/pacman.d/hooks/omarchy-guardian.hook

if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' "Run this with sudo." >&2
    exit 2
fi
if [ ! -f "$HOOK_SOURCE" ]; then
    printf '%s\n' "The omarchy-guardian package is not installed ($HOOK_SOURCE is missing)." >&2
    exit 2
fi

install -d /etc/pacman.d/hooks
ln -sfn "$HOOK_SOURCE" "$HOOK_TARGET"
printf '%s\n' "Enabled the Guardian pacman hook: $HOOK_TARGET"

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    /usr/bin/runuser --login \
        --command /usr/lib/omarchy-guardian/install-user-interceptor.sh \
        "$SUDO_USER"
else
    printf '%s\n' "No invoking user found; theme command interception was not added to a Bash profile." >&2
fi

printf '%s\n' "Enable the AUR gate for your user with: yay --makepkg /usr/lib/omarchy-guardian/guardian-makepkg --save -P --stats"
