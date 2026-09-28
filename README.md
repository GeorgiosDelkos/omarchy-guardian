# Omarchy Guardian

Omarchy Guardian inspects downloaded source code before you run or install it
on Arch Linux / Omarchy. It is an early, heuristic tool: a clear result is not
a safety guarantee.

It is a single Rust binary with **no third-party crates**. SHA-256, JSON, and
the small subset of TOML it needs are implemented in the crate so the whole
gate can be audited in one place. It builds only for Linux.

## Commands

```sh
omarchy-guardian scan ./downloaded-project
omarchy-guardian scan --thorough --hashes ./theme-checkout
omarchy-guardian guard --thorough ./aur-build-directory -- makepkg --noconfirm
omarchy-guardian sandbox ./theme-checkout -- /usr/bin/true
```

- `scan` reviews a file or directory and prints a report.
- `guard` reviews, then re-hashes the tree, then **replaces itself** with the
  command (`exec`) only if the review was clear and nothing changed.
  `--exclude NAME` (repeatable) leaves a top-level directory out of both the
  review and the snapshot.
- `sandbox` reviews, copies the tree to a private temporary directory, proves
  the copy matches the reviewed snapshot, and runs the command in Bubblewrap
  with the network isolated, no host home directory and a read-only system.
  It is a behaviour smoke test, not a dynamic malware detector.

Exit codes: `0` clear (or a scriptlet-free pacman transaction), `1` findings,
`2` incomplete review or usage error. Once `guard` or `sandbox` starts the
command, the exit code is the command's own (128 + signal if it was killed).
Guardian announces on stderr when it starts the command, so its own blocks can
be told apart from the command's failures.

## What is checked

- **Local rules** on every text file except prose (`*.md`, `*.rst`, `README`,
  `LICENSE`, ...): download-to-shell pipelines, encoded command execution,
  credential file access, destructive commands (a recursive `rm` of `/` or
  `$HOME` itself, `mkfs`, raw-disk writes), persistence, shell execution,
  privilege escalation, disabled TLS verification and likely credential
  exfiltration. Identifier patterns respect word boundaries, so `retrieval(`
  and `model.eval()` do not match `eval(`. Prose is still sent to the AI review.
- **Network destinations:** literal HTTP(S) hosts in code and runtime config,
  flagging cleartext HTTP and hard-coded IP addresses. URL paths, queries and
  credentials are never printed.
- **Dependencies:** `Cargo.lock`, npm lockfiles, `poetry.lock`, `go.sum` and
  exactly pinned `requirements*.txt` are checked with the public OSV API (only
  package names and versions are sent). Advisory severities and summaries are
  fetched per advisory; ones OSV does not rate are shown as `UNRATED`. Any
  advisory blocks a gate. Unsupported lockfiles, manifests with dependencies
  but no lockfile, or an unavailable OSV API make the review incomplete.
- **AI review:** the reviewable text (up to 256 KiB) is sent to the OpenCode
  CLI **on stdin** (never in argv, which is size-limited and visible to other
  users) with every OpenCode tool and permission denied. The reply must echo a
  random per-run nonce that only exists in that input, so a reply that never
  saw the source is rejected. Files that look sensitive by path (`.env*`, SSH
  and cloud credentials, key files, names containing `secret`, `credential` or
  `token`) are withheld and make the review incomplete.
- **Integrity:** a SHA-256 manifest of every scanned file. `guard` and
  `sandbox` re-hash immediately before running the command.

The walk never follows symbolic links, including ones swapped in while it
runs: directories are read through verified `/proc/self/fd` handles and every
opened file is checked against its earlier `lstat`. Symlinks, special files,
non-UTF-8 file names, text files over 2 MiB, files over 512 MiB, unresolved
Git LFS pointers and an AI review that fails or is inconclusive all make the
review **incomplete**, never clear. `.git` is always skipped; `target`,
`node_modules`, `.venv`, `vendor`, `dist` and `build` are skipped unless
`--thorough` is given.

External helpers are run by absolute path (`/usr/bin/curl`, `/usr/bin/bsdtar`,
`/usr/bin/pacman`, ...) with a timeout and bounded output. OpenCode is looked
up in the absolute entries of `PATH` for `scan`, `guard` and `sandbox`. The
pacman hook only accepts a root-owned `/usr/bin/opencode` or
`/usr/local/bin/opencode`, because it gates a root transaction and a
user-writable reviewer could be replaced by user-level malware. OpenCode must
be configured with a working provider; source leaves the machine through that
provider.

## Install (Arch Linux / Omarchy)

```sh
cd packaging/arch
makepkg -si
sudo /usr/lib/omarchy-guardian/enable-system-hook.sh
yay --makepkg /usr/lib/omarchy-guardian/guardian-makepkg --save -P --stats
```

Installing the package activates nothing. `enable-system-hook.sh` links the
pacman hook into `/etc/pacman.d/hooks/` and adds the theme interceptor to the
invoking user's `~/.bashrc`.

### Pacman hook

A pre-transaction hook (`AbortOnFail`) that reviews the `.INSTALL` scriptlets
of the exact archives being installed:

- For `pacman -S`, each target's sync-database version (`pacman -Si`) is
  located in the configured `CacheDir`s (`pacman-conf`), and each archive's
  package name is confirmed with `pacman -Qqp`.
- For `pacman -U`, the archives named on pacman's command line are used,
  resolved against pacman's own working directory. Remote URLs are refused.

libalpm runs hooks as children of pacman after `chroot` + `chdir("/")`, so the
hook reads pacman's exact argv from `/proc/<pid>/cmdline` and its working
directory from `/proc/<pid>/cwd`, then drops to the invoking user (`sudo` or
`doas`) for the review. Transactions it cannot attribute to pacman, to an
invoking user, or to an archive are blocked. Front ends that call libalpm
directly (for example pamac) are not supported and will be blocked.

### yay makepkg gate

Runs `guard --thorough --exclude src --exclude pkg` on the AUR build directory
before every `makepkg` invocation. The PKGBUILD, install scripts, patches and
other AUR inputs are reviewed; makepkg's own `src/` and `pkg/` work
directories (extracted upstream sources and build output) are not, so upstream
sources and whatever `prepare()`/`build()` do with them are outside the review.

### Omarchy themes

The Bash interceptor routes `omarchy theme install` and `omarchy theme update`
through Guardian. Themes are cloned to a hidden staging directory and
reviewed; only the exact reviewed checkout is moved into place and applied.
Updates stage and review every Git-installed theme before replacing any.
Themes with local or ignored modifications, submodules, or unresolved Git LFS
files are refused. Direct invocations of Omarchy binaries outside the
interactive Bash wrapper are not intercepted.

### Removal

```sh
yay --makepkg /usr/bin/makepkg --save -P --stats
sudo pacman -R omarchy-guardian
```

Removing the package removes the hook link. Delete the marked Guardian line
from `~/.bashrc` to stop theme interception.

## Limitations

A clean result only means the static checks, the configured AI provider and
the available OSV data did not identify a problem in the files reviewed.
Guardian can miss malicious behaviour and benign code can match a rule. It does
not inspect compiled package payloads, cannot prove an installed binary was
built from the reviewed source, and does not intercept direct downloads or
`curl | sh`. The sandbox is optional and limited to a 120 s run.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

On a non-Linux workstation, check with
`cargo clippy --target x86_64-unknown-linux-gnu --all-targets -- -D warnings`
(the crate refuses to build for other systems). Local hooks run the same
checks: `prek install` (see `.pre-commit-config.yaml`). CI builds and tests on
an Arch Linux container.

The integration gates (pacman hook, yay shim, theme install and update) have an
end-to-end harness that runs the real scripts in a Bubblewrap sandbox with a
throwaway `/usr` overlay, mock `makepkg`/`omarchy-theme-set`, a simulated pacman
parent process and a throwaway `HOME`:

```sh
cargo build --release
bash tests/e2e/integration-gates.sh
```

It needs `bwrap` 0.9 or newer, `bsdtar`, `pacman`, `git`, `flock`, `curl` and a
working `opencode`; it exits `77` when OpenCode cannot run, because every gate
is fail-closed on a failed AI review.
