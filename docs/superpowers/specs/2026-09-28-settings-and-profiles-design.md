# Settings and profiles — design

Date: 2026-09-28
Status: approved in brainstorming; awaiting written-spec review

## 1. Goal

Give Omarchy Guardian a settings layer so that:

- normal users get safe defaults that do not break system updates;
- cautious users can make every gate strict, and privacy-minded users can keep
  source on their machine;
- the AI reviewer's model and thinking level are configurable, globally and per
  kind of source;
- no setting can be used to weaken the root pacman gate from user level.

This is the first of four sub-projects. The others (smarter review engine,
wider Omarchy coverage, normal-user experience) get extension points here but
are designed separately.

### Stated by the owner

- Build settings and profiles first; model and thinking level are settings.
- Default behaviour when the AI review is unavailable: split by risk
  (community sources block, official repo updates proceed with a warning).
- Setup through a config file plus an interactive wizard.
- Layered config with tighten-only user overrides for privileged gates.
- **No dependencies anywhere.**

### Assumptions (open to correction)

- Omarchy users run `sudo`, so the wizard may ask for it to write the system file.
- OpenCode remains the only AI backend.

## 2. Hard constraints

1. **Zero crates.** `[dependencies]`, `[dev-dependencies]` and
   `[build-dependencies]` stay empty; `Cargo.lock` contains only
   `omarchy-guardian`. Enforced by a unit test that parses `Cargo.lock` with the
   in-crate TOML reader and by a CI step.
2. **No new runtime tools.** Only tools Guardian already calls or that ship with
   `pacman` itself (`pacman-conf`). The wizard does not use `gum` or any TUI
   library; prompts are plain reads and writes on `/dev/tty`.
3. **No weakening of the privileged gate from user level.** User-writable input
   (user config, environment, CLI flags of user-level commands) can only make
   privileged classes stricter.
4. Everything that exists today stays: stdin delivery with nonce, tool-less
   OpenCode permissions, root-owned OpenCode for the pacman hook, absolute tool
   paths, fail-closed handling of every gap other than "AI unavailable".

## 3. Source classes

Every review is tagged with the class of its source.

| Class | Source | Enforced by | Privileged |
|---|---|---|---|
| `official` | `pacman -S` from a repo in `official_repos` whose SigLevel requires signatures | pacman hook | yes |
| `third-party-repo` | `pacman -S` from any other repo, signed or not | pacman hook | yes |
| `local-package` | `pacman -U` archives | pacman hook | yes |
| `aur` | yay makepkg shim | user | no |
| `theme` | Omarchy theme install/update handler | user | no |
| `plugin` | reserved for the coverage sub-project's plugin gate | user | no |
| `source` | explicit `scan` / `guard` / `sandbox` (default) | user | no |

`official_repos` defaults to `core, extra, multilib, core-testing,
extra-testing, multilib-testing, omarchy` and is settable only in the system
file.

## 4. Per-class policy

| Knob | Values (loosest → strictest) | Meaning |
|---|---|---|
| `ai` | `off` → `optional` → `required` | whether the AI review runs, and whether its absence blocks |
| `on_findings` | `warn` → `block` | what local-rule and OSV findings do |
| `on_ai_suspicious` | `warn` → `block` | what an AI `suspicious` verdict or any AI finding does |
| `thinking` | `default` → `minimal` → `low` → `medium` → `high` → `max` | reasoning level passed to OpenCode |
| `model` | `provider/model` or unset | per-class model override (no strictness order) |
| `timeout_secs` | integer 10..=900 | AI review timeout (no strictness order) |
| `confirm` | `false` → `true` | with `ai = off`: ask the user to approve after clean local checks (user-level classes only, §5) |

Rules that no setting changes:

- An AI reply that is malformed, lacks the nonce, uses a tool, or is
  `inconclusive` always blocks (INCOMPLETE). Only *unavailability* (no binary,
  spawn failure, provider/model/variant error, timeout, non-zero exit without a
  review) follows `ai`.
- Every other gap (unreadable files, symlinks, non-UTF-8 names, oversized text,
  withheld sensitive files, failed OSV audit, LFS pointers) blocks.

## 5. Profiles

A profile is a named preset for every knob of every class.

| Profile | `official` | `third-party-repo`, `local-package`, `aur`, `theme`, `plugin`, `source` |
|---|---|---|
| `standard` (default) | `ai = optional`, `thinking = low`, `on_findings = warn`, `on_ai_suspicious = block` | `ai = required`, `thinking = high`, `on_findings = block`, `on_ai_suspicious = block` |
| `strict` | `ai = required`, `thinking = medium`, `on_findings = block`, `on_ai_suspicious = block` | `ai = required`, `thinking = max`, `on_findings = block`, `on_ai_suspicious = block` |
| `local-only` | `ai = off`, `on_findings = warn` | `ai = off`, `on_findings = block`, plus `confirm = true` (see below) |

`confirm` (only meaningful with `ai = off`): after clean local checks, ask the
user on `/dev/tty` to approve; no TTY or no answer means block. Not settable
for privileged classes (the pacman hook runs without a reliable TTY); for them
`local-only` relies on `on_findings`.

Rationale for `official` warning under `standard`: signed Arch `.INSTALL`
scripts routinely contain `setcap`, `chown root` and `systemctl`, which local
rules flag; blocking would break ordinary updates. The AI verdict is the
blocking signal for signed official packages.

`timeout_secs` defaults by thinking level: 120 up to `medium`, 180 for `high`,
300 for `max`.

## 6. Config files

Two files, same format:

- system: `/etc/omarchy-guardian/config.toml`
- user: `$XDG_CONFIG_HOME/omarchy-guardian/config.toml`, default
  `~/.config/omarchy-guardian/config.toml`

```toml
profile = "standard"             # standard | strict | local-only

official_repos = ["core", "extra", "multilib", "omarchy"]   # system file only

[agent]
model = "anthropic/claude-sonnet-5"   # omit for OpenCode's default
max_input_kib = 256                   # 16..=1024

[agent.variants]                      # optional: portable level -> provider variant
max = "xhigh"

[class.official]
model = "anthropic/claude-haiku-4-5"
thinking = "low"

[class.aur]
thinking = "max"
on_findings = "block"
ai = "required"
timeout_secs = 300
```

Allowed keys: top-level `profile`, `official_repos`; `[agent]` `model`,
`max_input_kib`; `[agent.variants]` keys from the thinking scale with string
values; `[class.<name>]` keys `ai`, `on_findings`, `on_ai_suspicious`,
`thinking`, `model`, `timeout_secs`, `confirm`. Anything else is an error
naming file, line and key.

### Resolution

For each class, each knob resolves as:

1. the built-in value from the effective profile;
2. overridden by an explicit system-file value;
3. then the user file:
   - **user-level classes**: an explicit user value overrides;
   - **privileged classes**: a user value applies only if it is at least as
     strict as the value from steps 1–2; otherwise it is ignored with a warning.
     `thinking`, `model`, `timeout_secs`, `[agent]`, `[agent.variants]` and
     `official_repos` are system-only for privileged classes: never taken from
     the user file or a user profile, tighter or not (a level or model the
     provider rejects would make the root gate's review unavailable).

The effective profile is the system file's `profile` (default `standard`). A
user `profile` applies to user-level classes, and to privileged classes only
knob-by-knob under the tighten-only rule.

`--profile NAME` on `scan`/`guard`/`sandbox` replaces the user file's profile
for that run; it cannot affect privileged classes (those commands never review
them).

### Validation and failure

- Unknown keys, wrong types and out-of-range values are errors.
- System file must be a regular file owned by uid 0, not group/other writable,
  in a directory with the same properties; otherwise it is *insecure*.
- Invalid user file: ignored entirely, warning printed. Safe because it can
  only tighten privileged classes, and user-level classes fall back to system
  and profile values.
- Invalid or insecure system file: every privileged class blocks with a message
  naming `omarchy-guardian config check`; user-level classes use built-in
  `standard` merged with the user file, with a warning.
- Missing files are not errors.

## 7. Agent settings

- `thinking` is passed as `--variant <name>` only when `[agent.variants]` maps
  the level (system file for privileged classes; system then user file
  otherwise), because variant names are provider-specific. An unmapped level
  sends no variant and is shown as `<level> (provider default)`. The setup
  wizard maps the level it tested (`<level> = "<level>"`) in both files.
- `model` (class override, else `[agent] model`) is passed as `--model`.
- `max_input_kib` replaces the fixed 256 KiB limit.
- A rejected model or variant is AI unavailable, with the setting named in the
  error.
- The report headline line for the agent reads
  `OpenCode: <STATUS> · <model or "default model"> · <thinking> · profile <name>`.

## 8. Classification in the pacman hook

- `-U`: every target is `local-package`.
- `-S`: the `Repository` field of each target's `pacman -Si` block names the
  repo. The class is `official` when the repo is in `official_repos` and
  `pacman-conf --repo=<repo> SigLevel` output does not contain `Never`,
  `Optional`, `PackageNever`, `PackageOptional` or `PackageTrustAll`; otherwise
  `third-party-repo`. `pacman-conf` output is read with `LC_ALL=C`.
- A target with several repositories takes the strictest class among them.
- Each target's scriptlet is judged with its own class policy. Scriptlets that
  share `(model, thinking, timeout)` are reviewed in one AI call; findings are
  attributed back by virtual path.
- The transaction outcome is the most severe per-target outcome.

## 9. Outcomes

`Report::decide(&Policies) -> Decision`:

| Decision | Exit | When |
|---|---|---|
| `Clear` | 0 | nothing found, review complete |
| `Warned` | 0 | only findings whose policy is `warn`, or AI unavailable under `ai = optional` |
| `Limited` | 0 | nothing reviewable (scriptlet-free transaction) |
| `Blocked(Findings)` | 1 | any finding whose policy is `block` |
| `Blocked(Incomplete)` | 2 | any non-AI gap, or an invalid AI reply |
| `Blocked(AiUnavailable)` | 2 | AI unavailable under `ai = required` |
| `Blocked(NotConfirmed)` | 2 | `confirm = true` and the user did not approve |

Headlines: `CLEAR`, `WARNED`, `LIMITED REVIEW`, `HIGH RISK` / `REVIEW REQUIRED`,
`INCOMPLETE`, `AI REVIEW UNAVAILABLE`, `NOT CONFIRMED`. `guard` and `sandbox`
run the command for `Clear` and `Warned` only.

## 10. Commands

- `omarchy-guardian setup` — wizard (§11).
- `omarchy-guardian config show [--class NAME]` — effective policy per class,
  each value tagged `profile`, `system` or `user`, plus ignored user values and
  why.
- `omarchy-guardian config check` — validates both files and the system file's
  ownership; exit 0 valid, 2 invalid.
- `omarchy-guardian config path` — prints both paths.
- `scan` / `guard` gain `--class NAME` (default `source`, user-level classes
  only) and `--profile NAME`.
- Shims: yay shim passes `--class aur`; theme handler passes `--class theme`.
- `pacman-hook` reads only the system file for privileged decisions and the
  user file for tightening.

## 11. Setup wizard

All I/O on `/dev/tty` through an injected reader/writer.

1. Detect OpenCode on the user's PATH and whether a root-owned
   `/usr/bin/opencode` or `/usr/local/bin/opencode` exists; explain that the
   pacman gate needs the latter. No OpenCode: recommend `local-only`.
2. Choose profile (numbered list, one line each; default `standard`).
3. Choose model from `opencode models` output (first entry: OpenCode default);
   optionally a separate model for `official`. If `opencode models` fails,
   accept free text in `provider/model` form or empty for default.
4. Choose thinking level for community classes (default from profile).
5. Test run with two built-in samples (one `curl ... | sh`, one clean). Pass =
   both replies valid with nonce, bad flagged, clean not flagged. Show latency.
   On failure: retry, change model/level, or abort; nothing written.
6. Write the user file atomically (temp file in the same directory + rename,
   mode 0644). Show the system file diff; on confirmation run
   `sudo install -m 0644 -o root -g root <temp> /etc/omarchy-guardian/config.toml`
   (creating the directory with `sudo install -d -m 0755`). Both are validated
   before writing.
7. Print next steps if the pacman hook link or yay shim is not active.

Files written by the wizard carry a header comment naming the wizard and
pointing at `config show`.

## 12. Code structure

| Unit | Responsibility |
|---|---|
| `config/model.rs` | `Profile`, `SourceClass`, knob enums with a total strictness order, `Policy`, `AgentSettings`, built-in profile tables |
| `config/file.rs` | strict parse of one file into `PartialConfig` with `ConfigError { file, line, key, message }` |
| `config/resolve.rs` | merge profile → system → user; tighten-only; records the origin of every value and every ignored value |
| `config/load.rs` | locate files, ownership check (injected), produce `Settings` or the privileged-block state |
| `tomlish.rs` | add typed accessors: string, integer, boolean, string array |
| `classify.rs` | repo → class from `pacman -Si` and `pacman-conf` output |
| `agent.rs` | `review(binary, files, &AgentSettings)`; error split into `Unavailable` vs `Invalid` |
| `report.rs` | findings carry their class; `decide`; new headlines; agent line |
| `pacman.rs` | per-target class and policy; grouped AI calls |
| `setup.rs` | wizard |
| `cli.rs` | new flags and subcommands |

## 13. Testing

- Profile table: every profile × class × knob matches §5.
- Tighten-only, exhaustive: for every privileged class, every knob, every
  (system value, user value) pair, the result is never looser than the system
  value.
- Parser: each allowed key; unknown keys, wrong types, out-of-range values,
  duplicate keys, with correct line numbers.
- Loader: insecure system file (injected ownership) blocks privileged classes;
  invalid user file ignored; missing files fine.
- Decision matrix: every combination of (findings present, AI state, policy) →
  decision and exit code per §9.
- Classification: sample `pacman -Si` and `pacman-conf` outputs, multi-repo
  targets, unsigned and signed third-party repos.
- Agent: mock OpenCode asserts `--model` and `--variant` in argv; unavailable
  vs invalid classification; timeout per level.
- Wizard: scripted session for each profile, test-run failure path, no write
  on failure.
- Zero-dependency guard: test that `Cargo.lock` lists exactly one package and
  `Cargo.toml` dependency tables are empty; CI step runs `cargo tree --depth 1`
  and fails on any dependency line.
- E2E additions: `standard` with OpenCode unavailable → an official-class
  scriptlet passes as `WARNED` while the AUR shim blocks; `local-only` without
  a TTY blocks a theme install; an insecure system file blocks the pacman hook.

## 14. Out of scope

Chunked and diff-aware review, verdict caching by content hash, gates for
plugins, hooks, `curl | sh`, mise and webapps, PATH-independent AUR gating
during `omarchy update`, desktop notifications, Omarchy menu integration.
