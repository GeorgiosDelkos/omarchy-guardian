#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' "Run this installer with sudo from the project directory." >&2
    exit 2
fi

if [ ! -x "$ROOT/target/release/omarchy-guardian" ]; then
    printf '%s\n' "Build first with: cargo build --release" >&2
    exit 2
fi

install -Dm755 "$ROOT/target/release/omarchy-guardian" /usr/local/bin/omarchy-guardian
install -Dm755 "$ROOT/integrations/pacman/guardian-pacman-hook" /usr/local/lib/omarchy-guardian/guardian-pacman-hook
install -Dm755 "$ROOT/integrations/yay/guardian-makepkg" /usr/local/lib/omarchy-guardian/guardian-makepkg
install -Dm755 "$ROOT/integrations/omarchy/guardian-theme" /usr/local/lib/omarchy-guardian/guardian-theme
install -Dm644 "$ROOT/integrations/omarchy/omarchy-bash-interceptor.sh" /usr/local/lib/omarchy-guardian/omarchy-bash-interceptor.sh
install -Dm755 "$ROOT/integrations/omarchy/install-user-interceptor.sh" /usr/local/lib/omarchy-guardian/install-user-interceptor.sh
install -Dm644 "$ROOT/integrations/pacman/omarchy-guardian.hook" /etc/pacman.d/hooks/omarchy-guardian.hook

theme_interceptor_installed=false
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    /usr/bin/runuser --login \
        --command /usr/local/lib/omarchy-guardian/install-user-interceptor.sh \
        "$SUDO_USER"
    theme_interceptor_installed=true
else
    printf '%s\n' "No invoking user found; theme command interception was not added to a Bash profile." >&2
fi

printf '%s\n' "Installed the Pacman hook, yay/makepkg gate, and Guardian theme handler."
printf '%s\n' "Enable the AUR gate for this user with: yay --makepkg /usr/local/lib/omarchy-guardian/guardian-makepkg --save -P --stats"
if [ "$theme_interceptor_installed" = true ]; then
    printf '%s\n' "Guardian theme install/update interception is loaded in new interactive Bash shells."
fi
