# Omarchy Guardian

Omarchy Guardian is an early prototype for inspecting downloaded source code
before a user runs or installs it.

## Current prototype

Build, scan source, or gate a command on a clean review:

```sh
cargo build --release
cargo run -- scan ./downloaded-project
cargo run -- scan --thorough --hashes ./theme-checkout
cargo run -- guard --thorough ./aur-build-directory -- makepkg --noconfirm
cargo run -- sandbox ./theme-checkout -- /usr/bin/true
```

The scanner checks readable text files for suspicious patterns and asks the
installed OpenCode CLI to review the exact source text for security risks. The
review agent has tools disabled and is instructed to treat source as untrusted
data. It also checks for download-to-shell pipelines, encoded command
execution, access to common credential files, destructive system commands,
persistence changes, shell execution, and privilege escalation. It doesn't
follow symlinks and skips common generated/dependency directories (`.git`,
`target`, `node_modules`, `.venv`, `vendor`, `dist`, and `build`). Use
`--thorough` for install gates to include those directories (still excluding
`.git`). Binary assets are not source-reviewed; text files larger than 2 MiB
make the scan incomplete. Files over the 512 MiB integrity-hash limit also make
the scan incomplete. AI review input is limited to 256 KiB.
Files that look sensitive by path (such as `.env*`, SSH/AWS credentials,
private-key files, and names containing `secret`, `credential`, or `token`) are
withheld from the model, and the scan is reported as incomplete.

OpenCode must be installed, configured with a working model/provider, and
available as `opencode` in `PATH`. Source text is sent to the provider selected
by the user's OpenCode configuration; that may be a local model or an external
service. If the agent cannot run or return a valid report, Guardian marks the
scan incomplete rather than reporting it as clean.

Exit codes:

- `0`: no concerning patterns found by the local checks or agent
- `1`: one or more concerning patterns found
- `2`: invalid usage or an incomplete scan

Reports lead with a colored verdict (`CLEAR`, `HIGH RISK`/`REVIEW REQUIRED`,
`INCOMPLETE`, or `LIMITED REVIEW`), then coverage, alert counts, local matches,
and the OpenCode assessment. ANSI colors are used only for a terminal and are
disabled when `NO_COLOR` is set.

## Additional checks

- **Network requests:** Guardian inventories literal HTTP(S) destinations in
  source/config files, flags cleartext HTTP and hard-coded IP destinations, and
  looks for same-line combinations of sensitive-data access and outbound sends.
  This is static analysis; it does not rate destination reputation or observe
  live traffic.
- **Dependencies:** `Cargo.lock`, npm lockfiles, `poetry.lock`, `go.sum`, and
  exactly pinned `requirements*.txt` entries are checked with the public OSV
  API. Only package coordinates and versions are sent to OSV. Unsupported lock
  formats, missing locks for declared dependencies, or an unavailable OSV check
  make the scan incomplete.
- **Integrity:** Guardian prints a SHA-256 manifest for scanned files. `guard`
  re-hashes and compares the file set immediately before it starts the guarded
  command; `sandbox` verifies its temporary copy against that same manifest.
  Use `scan --hashes <path>` to print individual hashes. This ties the action to
  the reviewed files, but does not prove that a compiled or installed binary
  came from that source.
- **Sandbox:** `sandbox` first requires a clean review, then runs the requested
  command with Bubblewrap in a disposable copy, with network isolated, no host
  home directory, and the system filesystem mounted read-only. It is an
  optional behavior smoke test, not a complete dynamic malware detector.

## Important limitations

This is an AI-assisted heuristic prototype, not a guarantee that software is
safe. It can miss malicious behavior, and benign code can match a rule. A clean
result only means the configured agent, static checks, and available OSV audit
didn't identify a problem in the files they reviewed. The reviewer has no
tools, but source still leaves the machine through the configured
model/provider. The dependency check sends package names and versions to OSV.
Guardian does not inspect compiled package payloads or all dependency-lockfile
formats, and it cannot establish that an installed binary was built from the
scanned source. The `guard` command runs its requested command only after a
clear review and a matching SHA-256 snapshot.

## Tests

`cargo test` runs the scanner, hashing, dependency, reporting, and guard unit
tests. The integration gates (Pacman hook, yay shim, and theme
install/update) are covered end to end by:

```sh
cargo build --release
bash tests/e2e/integration-gates.sh
```

That harness runs the real integration scripts inside a Bubblewrap sandbox with
the freshly built binary mounted at `/usr/local/bin/omarchy-guardian`, mock
`makepkg`/`omarchy-theme-set` commands, and a throwaway `HOME`, so it installs
nothing and never touches the live system. It needs `bwrap`, `bsdtar`, `git`,
`flock`, `curl`, and a working `opencode` review; it exits `77` when OpenCode
cannot run, because the gates are fail-closed on a failed AI review.

## Pacman and yay integration

The repository includes an opt-in Pacman pre-transaction hook and a yay
`makepkg` shim:

1. Install the Pacman hook and helper binaries with `cargo build --release`
   followed by `sudo integrations/install-system-hook.sh`.
2. Configure yay to use the Guardian shim for `makepkg`:

   ```sh
   yay --makepkg /usr/local/lib/omarchy-guardian/guardian-makepkg --save -P --stats
   ```

The Pacman hook runs before install/upgrade transactions and uses
`AbortOnFail`. For repository sync installs it reviews the `.INSTALL`
scriptlets in matching package archives from Pacman's standard cache. For
`pacman -U` it reviews scriptlets in the exact package archive paths supplied
to Pacman. The hook drops root privileges before invoking Guardian/OpenCode;
transactions without an identifiable invoking user, package archive, or valid
review are blocked.

The yay shim runs Guardian against the AUR build directory before each
`makepkg` invocation and only starts `makepkg` after a clean result. This means
it reviews the checked-out PKGBUILD and other text already present in the build
directory; it does not safely stage and review upstream source archives before
makepkg downloads or executes build steps.

These integrations do not inspect compiled package payloads or prove that an
installed binary matches reviewed source. Pacman sync packages are binary
artifacts, so this hook currently reviews their install scriptlets only. Direct
downloads and arbitrary `curl | sh` commands are not intercepted. The system
hook is opt-in and is not activated merely by building the project.

The system installer adds an interactive Bash function so `omarchy theme install`
and `omarchy theme update` pass through Guardian. Other Omarchy commands are
forwarded to the stock dispatcher. Open a new Bash shell after installation for
the function to load. Theme installs are cloned to a hidden staging directory
and reviewed before the exact checkout is moved into the user theme directory
and applied. Theme updates stage and review every Git-installed theme before
replacing any of them; themes with local or ignored modifications are refused.
Themes using Git submodules or unresolved Git LFS files fail closed. Direct
invocations of Omarchy binaries outside the interactive Bash wrapper bypass
this interception.

The theme test uses a temporary `hyprland.lua` that tries to send an SSH private
key to an external host. Guardian reports the credential access and shell
execution and blocks a mocked installer; it does not change the active theme.

To remove the system integration, restore yay's setting first with
`yay --makepkg /usr/bin/makepkg --save -P --stats`, then remove
`/etc/pacman.d/hooks/omarchy-guardian.hook` and
`/usr/local/lib/omarchy-guardian/`. Remove the marked Guardian source line from
`~/.bashrc` to disable theme command interception.
