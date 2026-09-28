# Smarter review engine — design

Date: 2026-09-28
Status: approved in brainstorming; awaiting written-spec review

## 1. Goal

Make the AI review scale to real packages and cost less to repeat, without
loosening any verdict:

- large sources are reviewed in several AI calls instead of being refused as
  "input too large";
- an upgrade of a source the user already approved is reviewed as a diff plus
  its risky files, not re-read from scratch;
- identical content reviewed with identical settings is not paid for twice;
- the AI is told what to look for on an Omarchy machine.

This is the second of four sub-projects (after settings and profiles). Wider
Omarchy coverage and the normal-user experience follow and route their
reviews through this engine.

### Stated by the owner

- Include all four capabilities: chunked review, diff-aware upgrades, verdict
  cache, risk-focused prompting.
- Cache and baselines apply to user-level classes only; pacman classes always
  get a full, fresh review.
- On an upgrade, send the diff plus the risky files in full.

### Assumptions (open to correction)

- "Smarter" means fewer incomplete blocks and fewer paid calls, never a
  looser verdict.
- When Guardian cannot review something, it keeps saying so.

## 2. Hard constraints

- Zero crates. The diff, store and cache are written in-crate; hashing uses
  the existing `sha256` module.
- Arch Linux / Omarchy only, as today.
- Nothing user-writable may weaken the root pacman gate: pacman classes
  (`official`, `third-party-repo`, `local-package`) never read or write the
  store, and never use diff mode.
- The reply contract with the AI (nonce, status, findings) is unchanged, and
  every chunk is judged by the existing rules: an invalid reply always blocks,
  an unavailable AI follows the class policy.
- The existing `Decision` values and exit codes are unchanged.

## 3. Architecture

```
scan::walk ──> files + local findings
                 │
          plan::build(files, findings, baseline?, settings)   [pure]
                 │   ranks by risk, applies diff mode, packs chunks
                 ▼
          ReviewPlan { chunks: Vec<Chunk>, manifest, gaps }
                 │
          execute(plan): per chunk -> cache lookup -> agent::review -> cache store
                 │
          merge: worst verdict wins -> AgentOutcome -> Decision (unchanged)
                 │
          on a complete AI "clear" -> baseline::record(identity, snapshot)
```

New modules under `src/engine/`:

| Module | Responsibility |
|---|---|
| `plan.rs` | Risk ranking, diff-mode selection per file, chunk packing. Pure. |
| `diff.rs` | Line-based Myers diff producing unified hunks. |
| `store.rs` | Content-addressed blobs and atomic writes under the state dir. |
| `cache.rs` | Verdict cache keyed by prompt version, agent settings, class and chunk bytes. |
| `baseline.rs` | Approved snapshots per source identity. |
| `mod.rs` | `execute` and `merge`: runs a plan through the cache and `agent::review`. |

`review.rs` keeps the scan, local rules and dependency audit; its
`run_agents` becomes a call into `engine`. `agent.rs` keeps the OpenCode
invocation and reply parsing; `build_request` gains the trusted header and
the local-findings block (section 5).

## 4. Risk ranking and chunks

### Tiers

- **Tier 0, entry points** — always sent in full, first:
  `PKGBUILD`, `*.install`, `.INSTALL`, `Makefile`, `CMakeLists.txt`,
  `meson.build`, `build.rs`, `setup.py`, `pyproject.toml`, `package.json`,
  top-level `*.sh`, systemd units, `.desktop` files, Hyprland config
  (`*.conf` containing `exec`), plugin `*.qml`, and any file with a local
  finding.
- **Tier 1, code and runtime config** — whatever
  `rules::is_executable_or_runtime_config` matches and tier 0 did not.
- **Tier 2, everything else** — documentation (`rules::is_documentation`)
  sorts last within this tier.

Within a tier, files sort by path so plans are deterministic.

### Packing

- Items pack whole, in tier order, into chunks whose request is at most
  `max_input_bytes`. Packing is first-fit in order; a later small item never
  jumps ahead of an earlier tier.
- An item larger than one chunk splits on line boundaries; each piece is
  labelled `path (lines a–b of n)`.
- If tier 0 alone needs more than `max_chunks` chunks, the review is
  incomplete (`Gap::AgentInputTooLarge`) and no AI call is made.
- If all tiers need more than `max_chunks` chunks, the review is incomplete
  (`Gap::AgentInputTooLarge`) and no AI call is made. A partial AI review is
  never presented as a review of the whole source.
- Every chunk carries the full manifest (every path, size, and whether it is
  sent whole, as a diff, or unchanged) so the AI knows what exists.

### Diff mode

Applies only when the class's `diff` knob is `on`, the target has an
identity, and a valid baseline exists for it.

| File | Sent as |
|---|---|
| Tier 0 | Whole, always |
| Tier 1–2, new or renamed | Whole |
| Tier 1–2, changed | Unified diff, 3 lines of context |
| Tier 1–2, unchanged | Manifest entry "unchanged since approved version" only |
| Removed since baseline | Manifest entry "removed" only |

Local rules and the dependency audit always run on the whole tree,
regardless of diff mode.

## 5. Prompt

`PROMPT_VERSION` (an integer constant in `agent.rs`) is part of every cache
key; any prompt change bumps it.

The trusted part of the request, written by Guardian, adds:

- the source class, and "first review" or "upgrade of an approved version";
- "chunk k of n" and the manifest;
- an Omarchy checklist of what to look for:
  - autostart: Hyprland `exec` / `exec-once`, `~/.config/systemd/user`,
    `~/.config/autostart`;
  - Omarchy hooks: `~/.config/omarchy/hooks/<name>` and `<name>.d/*`
    (post-update, theme-set, font-set, post-boot, battery-low,
    pre-refresh-pacman);
  - Omarchy shell plugins under `~/.config/omarchy/plugins`;
  - PATH shadowing via `~/.local/bin`; shell rc edits;
  - privilege: sudoers, pacman hooks, setuid;
  - credential reads: `~/.ssh`, browser profiles, OpenCode and other AI
    tool credentials, keyrings, password stores;
  - input and clipboard capture: `hyprctl`, `wl-paste`, `wtype`, uinput;
  - download-and-execute (`curl … | sh`), obfuscated or encoded payloads.

The untrusted part adds, before the files, the local findings (rule, file,
line, excerpt). They sit inside the untrusted block because their excerpts
are untrusted text. The AI is asked to confirm or dismiss each, and its
answer does not remove a local finding.

The reply format is unchanged.

## 6. Store

- Location: `$XDG_STATE_HOME/omarchy-guardian/`, default
  `~/.local/state/omarchy-guardian/`. Directories 0700, files 0600.
- Every write is a temp file opened `create_new` in the same directory, then
  `rename`.
- If the store directory is not owned by the current user, or is group- or
  world-writable, the store is not used for this run and the report carries
  `Gap::StoreUnavailable` (section 9).
- Pacman classes never open the store. The pacman hook never passes
  `--identity`.

Layout:

```
blobs/<sha256>                         file contents; re-hashed on every read
baselines/<class>/<sha256(identity)>   manifest (below)
verdicts/<cache-key>                   one cached chunk verdict
```

Baseline manifest (text, one record per line):

```
omarchy-guardian-baseline 1
identity <identity>
recorded <unix seconds>
file <sha256> <size> <path>
...
```

Verdict entry (JSON, written with the in-crate JSON writer): `key`,
`status`, `summary`, `findings`, `model` label, `recorded` unix seconds.

## 7. Verdict cache

- Key: SHA-256 of `PROMPT_VERSION`, model, variant, thinking level, source
  class, and the exact chunk request with the nonce removed.
- Stored: `clear` and `suspicious` verdicts from valid replies only. Never
  `inconclusive`, unavailable or invalid results.
- A hit is used only if the entry's stored `key` equals the lookup key and it
  is younger than `cache_days`. Otherwise it is deleted and treated as a
  miss.
- A hit shows in the report as "cached from <date>, <model>" for that chunk.
- If any chunk of a run is invalid, no chunk verdict from that run is stored.

## 8. Baselines

- Identity comes from a new `--identity <string>` flag on the review
  commands, set by the wrappers:
  - `guardian-makepkg`: `aur:<pkgbase>`, from `.SRCINFO`'s `pkgbase`, else
    the build directory's name;
  - `guardian-theme`: `theme:<normalized git remote URL>`;
  - explicit reviews of a path: `source:<canonical path>` when `--identity`
    is not given.
  - Plugins (sub-project 3 of 4) will use `plugin:<git URL>`.
- A baseline is recorded only when every chunk got an AI `clear` (live or
  cached), the report has no gaps, and the decision is `Clear`.
- A manifest that does not parse, or a blob whose hash does not match, means
  no baseline: that baseline is deleted and the review runs in full.

### Pruning

At the end of each review that used the store:

1. delete expired verdicts;
2. keep only the newest baseline per identity;
3. delete blobs no baseline references;
4. while the store exceeds `max_store_mib`, delete the oldest baseline and
   its unreferenced blobs.

## 9. Settings

New per-class policy knobs, loosest first:

| Knob | Values | standard | strict | local-only |
|---|---|---|---|---|
| `cache` | `on`, `off` | on | on | on (unused, AI off) |
| `diff` | `on`, `off` | on | off | on (unused, AI off) |

New agent settings, beside `max_input_kib`, with the same layering:

| Key | Default |
|---|---|
| `max_chunks` | 8 |
| `cache_days` | 30 |
| `max_store_mib` | 256 |

For pacman classes, `cache` and `diff` are always `off`; setting either for a
pacman class in any file is a config error, like other system-only keys.
`max_chunks` for pacman classes comes from the system file only.

`show` prints the new knobs per class and the store size and baseline count.

## 10. Commands

- `--identity <string>` on the review commands (section 8).
- `omarchy-guardian forget <identity>` removes that identity's baselines.
- `omarchy-guardian forget --all` removes every baseline and cached verdict.

## 11. Errors

A store or diff failure never blocks by itself; it falls back to a full
review in the same run.

| Failure | Result |
|---|---|
| Store unreadable, unwritable, wrong owner or mode | No cache, no baseline, full review; `Gap::StoreUnavailable(reason)` shown as a notice |
| Corrupt baseline or blob hash mismatch | Baseline deleted, full review |
| Diff input over 1 MiB for a file | That file sent whole |
| Any chunk invalid | Whole review blocked (existing invalid outcome); nothing cached from this run |
| Any chunk unavailable | Class's AI-unavailable policy; valid chunk verdicts from this run are cached |
| Tier 0 or whole plan over `max_chunks` | `Gap::AgentInputTooLarge`, no calls |
| A packed chunk over `max_input_bytes` | Planner bug: `debug_assert!`; incomplete in release |

`Gap::StoreUnavailable` is a notice: it does not make a review incomplete,
because the review itself still ran in full.

Merging chunk outcomes:

1. any invalid → the existing invalid outcome;
2. else any unavailable → the existing unavailable outcome;
3. else any `suspicious` → suspicious, with all chunks' findings;
4. else any `inconclusive` → inconclusive;
5. else clear.

## 12. Testing

No test uses the network.

- `plan.rs`: tier ordering; packing at exact limits; line splits with
  labelled ranges; tier-0 overflow and whole-plan overflow are incomplete;
  diff mode picks whole / diff / manifest-only per file; pacman classes never
  diff.
- `diff.rs`: known hunks; empty and identical inputs; no trailing newline;
  CRLF; over-size input falls back to whole.
- `store.rs`, `cache.rs`, `baseline.rs` in a temp dir: atomic write; refusal
  on wrong owner or mode; hash mismatch deletes; expiry; stored-key check;
  pruning order and size cap; baseline recorded only on a complete clear.
- `engine` executor with the existing fake OpenCode: worst verdict wins;
  invalid chunk 2 blocks and caches nothing; unavailable chunk still caches
  the valid ones; a cache hit makes no OpenCode call; the second run of an
  upgraded tree sends a diff plus the PKGBUILD.
- E2E (`tests/e2e/integration-gates.sh`): AUR reviewed twice shows "cached";
  an upgraded AUR tree sends a diff plus the PKGBUILD; a tree over
  `max_chunks` × limit is incomplete; pacman scriptlets are never cached.

## 13. Documentation

- README: a "How the review scales" section covering chunks, diffs, the
  cache, `forget`, and the trust boundary: user-level malware can poison the
  store, as it can already edit the user's shell rc files; the root pacman
  gate never reads it.
- The CI no-dependency check is unchanged.

## 14. Out of scope

Gates for plugins, hooks, `curl | sh`, mise and webapps, and AUR gating
during `omarchy update` (sub-project 3). Desktop notifications and menu
integration (sub-project 4). Root-owned or signed caches for the pacman gate.
