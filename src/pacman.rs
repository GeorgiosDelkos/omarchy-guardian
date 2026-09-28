//! The pacman pre-transaction hook: review the `.INSTALL` scriptlets of the
//! exact package archives a transaction is about to install.
//!
//! libalpm runs hooks as direct children of pacman after `chroot` +
//! `chdir("/")`, so the hook's own working directory says nothing about the
//! user's. The hook script passes pacman's PID and its working directory
//! (`/proc/<pid>/cwd`, readable only by root), and this module reads pacman's
//! exact argv from `/proc/<pid>/cmdline` instead of re-parsing a shell string.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

use crate::error::{Error, IoContext};
use crate::report::{Gap, Report};
use crate::review;
use crate::scan::MAX_TEXT_FILE_SIZE;
use crate::tools::{self, Limits, OpenCode};

const ARCHIVE_EXTENSIONS: &[&str] = &[".pkg.tar.zst", ".pkg.tar.xz", ".pkg.tar.gz", ".pkg.tar"];
const DEFAULT_CACHE_DIR: &str = "/var/cache/pacman/pkg/";
const TOOL_LIMITS: Limits = Limits {
    timeout_secs: 30,
    max_output: 4 * 1024 * 1024,
};
const C_LOCALE: &[(&str, &str)] = &[("LC_ALL", "C")];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookArgs {
    pub pacman_pid: u32,
    pub cwd: PathBuf,
    /// `SystemOnly` in production. The hook script passes `UserPath` only on
    /// its non-root branch, which pacman never takes; tests use it.
    pub opencode: OpenCode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Sync,
    LocalUpgrade,
}

pub fn review_transaction(args: &HookArgs) -> Result<Report, Error> {
    let targets = read_targets(io::stdin().lock())?;
    let argv = pacman_argv(args.pacman_pid)?;
    let operation = parse_operation(&argv)?;

    let mut report = Report::new("pacman transaction");
    let archives = match operation {
        Operation::Sync => sync_archives(&targets)?,
        Operation::LocalUpgrade => local_archives(&argv, &args.cwd)?,
    };

    for target in &targets {
        match archives.get(target) {
            Some(Ok(paths)) => {
                for archive in paths {
                    match scan_install_script(archive, target, &mut report) {
                        Ok(true) => {}
                        Ok(false) => {
                            println!("Pacman package {target}: no install scriptlet to review.");
                        }
                        Err(error) => report.gaps.push(Gap::Package(error)),
                    }
                }
            }
            Some(Err(reason)) => report
                .gaps
                .push(Gap::Package(Error::Refused(format!("{target}: {reason}")))),
            None => report.gaps.push(Gap::Package(Error::Refused(format!(
                "no package archive matched transaction target {target}"
            )))),
        }
    }

    review::run_agent(&mut report, &args.opencode);
    Ok(report)
}

fn read_targets(input: impl BufRead) -> Result<Vec<String>, Error> {
    let mut targets = Vec::new();
    for line in input.lines() {
        let line = line.at(Path::new("<stdin>"))?;
        let target = line.trim();
        if target.is_empty() {
            continue;
        }
        if !is_valid_package_name(target) {
            return Err(Error::Refused(format!(
                "invalid package target from pacman: {target:?}"
            )));
        }
        targets.push(target.to_string());
    }
    if targets.is_empty() {
        return Err(Error::Refused(
            "pacman hook received no package targets".into(),
        ));
    }
    Ok(targets)
}

/// Pacman package names: alphanumerics and `@._+-`, not starting with `-` or `.`.
pub fn is_valid_package_name(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric() || "@_+".contains(first))
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "@._+-".contains(character))
}

fn pacman_argv(pid: u32) -> Result<Vec<String>, Error> {
    let comm_path = PathBuf::from(format!("/proc/{pid}/comm"));
    let comm = fs::read_to_string(&comm_path).at(&comm_path)?;
    if comm.trim_end() != "pacman" {
        return Err(Error::Refused(format!(
            "the hook's parent process is {:?}, not pacman",
            comm.trim_end()
        )));
    }

    let cmdline_path = PathBuf::from(format!("/proc/{pid}/cmdline"));
    let cmdline = fs::read(&cmdline_path).at(&cmdline_path)?;
    split_cmdline(&cmdline)
}

fn split_cmdline(cmdline: &[u8]) -> Result<Vec<String>, Error> {
    let body = cmdline.strip_suffix(&[0]).unwrap_or(cmdline);
    body.split(|byte| *byte == 0)
        .map(|argument| {
            String::from_utf8(argument.to_vec())
                .map_err(|_| Error::Refused("pacman was given a non-UTF-8 argument".into()))
        })
        .collect()
}

/// Finds the pacman operation. Only sync (`-S`) and upgrade (`-U`)
/// transactions install scriptlets from archives Guardian can locate.
pub fn parse_operation(argv: &[String]) -> Result<Operation, Error> {
    for argument in argv.iter().skip(1) {
        match argument.as_str() {
            "--" => break,
            "--sync" => return Ok(Operation::Sync),
            "--upgrade" => return Ok(Operation::LocalUpgrade),
            _ => {}
        }
        if let Some(flags) = argument.strip_prefix('-')
            && !flags.starts_with('-')
        {
            if flags.contains('S') {
                return Ok(Operation::Sync);
            }
            if flags.contains('U') {
                return Ok(Operation::LocalUpgrade);
            }
        }
    }
    Err(Error::Refused(
        "only pacman sync (-S) and upgrade (-U) transactions are supported".into(),
    ))
}

/// Per-target archive lookup result: the archives, or why none was usable.
type Archives = HashMap<String, Result<Vec<PathBuf>, String>>;

/// For `-U`: every package archive named on the command line, resolved
/// against pacman's working directory and grouped by the package it holds.
fn local_archives(argv: &[String], cwd: &Path) -> Result<Archives, Error> {
    let mut archives: Archives = HashMap::new();

    for argument in argv.iter().skip(1) {
        if !is_package_archive_name(argument) {
            continue;
        }
        if argument.contains("://") {
            return Err(Error::Refused(format!(
                "remote package URLs are not supported: {argument}"
            )));
        }

        let path = cwd.join(argument);
        let metadata = fs::symlink_metadata(&path).at(&path)?;
        if !metadata.is_file() {
            return Err(Error::Refused(format!(
                "not a regular package archive: {}",
                path.display()
            )));
        }

        let name = package_name(&path)?;
        if let Ok(paths) = archives.entry(name).or_insert_with(|| Ok(Vec::new())) {
            paths.push(path);
        }
    }

    if archives.is_empty() {
        return Err(Error::Refused(
            "the upgrade did not name a readable package archive".into(),
        ));
    }
    Ok(archives)
}

/// For `-S`: the archive of each target's sync-database version in pacman's
/// cache directories, read once and indexed by file name.
fn sync_archives(targets: &[String]) -> Result<Archives, Error> {
    let versions = sync_versions(targets)?;
    let cache = cache_index(&cache_directories()?)?;
    let mut archives = Archives::new();

    for target in targets {
        let Some(candidates) = versions.get(target) else {
            archives.insert(
                target.clone(),
                Err("pacman has no sync database entry for it".into()),
            );
            continue;
        };

        let mut found = Vec::new();
        for version_arch in candidates {
            for extension in ARCHIVE_EXTENSIONS {
                if let Some(path) = cache.get(&format!("{target}-{version_arch}{extension}")) {
                    found.push(path.clone());
                }
            }
        }
        for path in &found {
            let name = package_name(path)?;
            if name != *target {
                return Err(Error::Refused(format!(
                    "{} contains {name}, not {target}",
                    path.display()
                )));
            }
        }

        let entry = if found.is_empty() {
            Err("no archive of the version being installed is in the pacman cache".into())
        } else {
            Ok(found)
        };
        archives.insert(target.clone(), entry);
    }
    Ok(archives)
}

/// `name → ["version-arch", ...]` from `pacman -Si`. A package present in
/// several repositories yields several candidates.
fn sync_versions(targets: &[String]) -> Result<HashMap<String, Vec<String>>, Error> {
    let mut args: Vec<OsString> = vec!["-Si".into(), "--".into()];
    args.extend(targets.iter().map(OsString::from));
    // Unknown targets make pacman exit non-zero while still printing the
    // others; those targets are then reported individually.
    let captured = tools::run(Path::new(tools::PACMAN), &args, None, C_LOCALE, TOOL_LIMITS)?;
    Ok(parse_sync_info(&String::from_utf8_lossy(&captured.stdout)))
}

pub fn parse_sync_info(output: &str) -> HashMap<String, Vec<String>> {
    let mut versions: HashMap<String, Vec<String>> = HashMap::new();
    let mut fields: HashMap<&str, &str> = HashMap::new();

    let mut flush = |fields: &mut HashMap<&str, &str>| {
        if let (Some(name), Some(version), Some(arch)) = (
            fields.get("Name"),
            fields.get("Version"),
            fields.get("Architecture"),
        ) {
            versions
                .entry((*name).to_string())
                .or_default()
                .push(format!("{version}-{arch}"));
        }
        fields.clear();
    };

    for line in output.lines() {
        if line.trim().is_empty() {
            flush(&mut fields);
        } else if let Some((key, value)) = line.split_once(':')
            && !line.starts_with(' ')
        {
            fields.insert(key.trim(), value.trim());
        }
    }
    flush(&mut fields);
    versions
}

fn cache_directories() -> Result<Vec<PathBuf>, Error> {
    let output = tools::run(
        Path::new(tools::PACMAN_CONF),
        &["CacheDir".into()],
        None,
        C_LOCALE,
        TOOL_LIMITS,
    )?
    .into_success()?;
    let directories: Vec<PathBuf> = String::from_utf8_lossy(&output)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect();
    if directories.is_empty() {
        Ok(vec![PathBuf::from(DEFAULT_CACHE_DIR)])
    } else {
        Ok(directories)
    }
}

/// Regular files in the cache directories by name. Symlinks are ignored.
fn cache_index(directories: &[PathBuf]) -> Result<HashMap<String, PathBuf>, Error> {
    let mut index = HashMap::new();
    for directory in directories {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).at(directory),
        };
        for entry in entries {
            let entry = entry.at(directory)?;
            let is_file = entry.file_type().at(directory)?.is_file();
            if let (true, Ok(name)) = (is_file, entry.file_name().into_string()) {
                index.entry(name).or_insert_with(|| entry.path());
            }
        }
    }
    Ok(index)
}

fn is_package_archive_name(name: &str) -> bool {
    ARCHIVE_EXTENSIONS
        .iter()
        .any(|extension| name.ends_with(extension))
}

fn package_name(archive: &Path) -> Result<String, Error> {
    let output = tools::run(
        Path::new(tools::PACMAN),
        &["-Qqp".into(), "--".into(), archive.into()],
        None,
        C_LOCALE,
        TOOL_LIMITS,
    )?
    .into_success()?;
    let name = String::from_utf8_lossy(&output).trim().to_string();
    if is_valid_package_name(&name) {
        Ok(name)
    } else {
        Err(Error::Refused(format!(
            "pacman reported an invalid package name for {}",
            archive.display()
        )))
    }
}

/// Extracts `.INSTALL` directly (no listing, which is unbounded for packages
/// with many files). Returns whether the archive had a scriptlet.
pub fn scan_install_script(
    archive: &Path,
    target: &str,
    report: &mut Report,
) -> Result<bool, Error> {
    let captured = tools::run(
        Path::new(tools::BSDTAR),
        &["-xOqf".into(), archive.into(), ".INSTALL".into()],
        None,
        C_LOCALE,
        Limits {
            timeout_secs: 30,
            max_output: usize::try_from(MAX_TEXT_FILE_SIZE).unwrap_or(usize::MAX),
        },
    )?;
    if !captured.status.success() {
        if String::from_utf8_lossy(&captured.stderr).contains("Not found in archive") {
            return Ok(false);
        }
        return Err(Error::ToolFailed {
            tool: "bsdtar".into(),
            detail: format!("{}: {}", archive.display(), captured.failure_detail()),
        });
    }

    let contents = String::from_utf8(captured.stdout).map_err(|_| {
        Error::Refused(format!(
            "package install script is not UTF-8: {}",
            archive.display()
        ))
    })?;
    let archive_name = archive
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("package");
    review::analyze_text(
        report,
        &format!("{target}/{archive_name}/.INSTALL"),
        &contents,
        false,
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use super::{
        Operation, is_valid_package_name, local_archives, parse_operation, parse_sync_info,
        read_targets, scan_install_script, split_cmdline,
    };
    use crate::report::Report;
    use crate::rules::RuleId;
    use crate::test_support::{TempDir, tool_available};

    fn argv(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn only_sync_and_upgrade_operations_are_accepted() {
        for (line, expected) in [
            ("/usr/bin/pacman -Syu", Operation::Sync),
            ("pacman -yuS foo", Operation::Sync),
            ("pacman --sync foo", Operation::Sync),
            ("pacman -U /tmp/a.pkg.tar.zst", Operation::LocalUpgrade),
            ("pacman --upgrade a.pkg.tar.zst", Operation::LocalUpgrade),
            (
                "/bin/sh /e2e/bin/pacman -U a.pkg.tar.zst",
                Operation::LocalUpgrade,
            ),
        ] {
            assert_eq!(parse_operation(&argv(line)).unwrap(), expected, "{line}");
        }
        for line in ["pacman -Rns foo", "pacman -Qs foo", "pacman -- -S"] {
            assert!(parse_operation(&argv(line)).is_err(), "{line}");
        }
    }

    #[test]
    fn cmdline_keeps_arguments_with_spaces() {
        assert_eq!(
            split_cmdline(b"pacman\0-U\0/tmp/with space.pkg.tar.zst\0").unwrap(),
            ["pacman", "-U", "/tmp/with space.pkg.tar.zst"]
        );
        assert!(split_cmdline(b"pacman\0\xff\0").is_err());
    }

    #[test]
    fn targets_must_be_package_names() {
        assert_eq!(
            read_targets(&b"linux\n\nlib32-glibc\n"[..]).unwrap(),
            ["linux", "lib32-glibc"]
        );
        assert!(read_targets(&b"\n"[..]).is_err());
        assert!(read_targets(&b"../etc\n"[..]).is_err());
        assert!(is_valid_package_name("gtk2+extra"));
        assert!(is_valid_package_name("@scope"));
        assert!(!is_valid_package_name("-rf"));
        assert!(!is_valid_package_name(".hidden"));
    }

    #[test]
    fn parses_sync_database_versions() {
        let output = "Repository      : core\nName            : linux\nVersion         : 6.10.1.arch1-1\nDescription     : The Linux kernel: and modules\nArchitecture    : x86_64\n\nRepository      : extra\nName            : ttf-font\nVersion         : 2:1.0-3\nArchitecture    : any\n";
        let versions = parse_sync_info(output);
        assert_eq!(versions["linux"], ["6.10.1.arch1-1-x86_64"]);
        assert_eq!(versions["ttf-font"], ["2:1.0-3-any"]);
    }

    #[test]
    fn remote_and_missing_archives_are_refused() {
        let dir = TempDir::new("pacman-missing");
        assert!(
            local_archives(
                &argv("pacman -U https://x.test/a-1-1-any.pkg.tar.zst"),
                dir.path()
            )
            .is_err()
        );
        assert!(
            local_archives(&argv("pacman -U missing-1-1-any.pkg.tar.zst"), dir.path()).is_err()
        );
        assert!(local_archives(&argv("pacman -U"), dir.path()).is_err());
    }

    fn build_package(dir: &Path, install: Option<&str>) -> std::path::PathBuf {
        fs::write(
            dir.join(".PKGINFO"),
            "pkgname = sample\npkgbase = sample\npkgver = 1.0-1\narch = any\n",
        )
        .unwrap();
        let mut members = vec![".PKGINFO"];
        if let Some(script) = install {
            fs::write(dir.join(".INSTALL"), script).unwrap();
            members.push(".INSTALL");
        }
        let archive = dir.join("sample-1.0-1-any.pkg.tar");
        let status = Command::new("/usr/bin/bsdtar")
            .arg("-cf")
            .arg(&archive)
            .args(&members)
            .current_dir(dir)
            .status()
            .unwrap();
        assert!(status.success());
        archive
    }

    #[test]
    fn relative_upgrade_archives_resolve_against_pacmans_directory() {
        if !tool_available("/usr/bin/bsdtar") || !tool_available("/usr/bin/pacman") {
            return;
        }
        let dir = TempDir::new("pacman-relative");
        let archive = build_package(dir.path(), None);

        let archives =
            local_archives(&argv("pacman -U sample-1.0-1-any.pkg.tar"), dir.path()).unwrap();
        assert_eq!(archives["sample"], Ok(vec![archive]));
    }

    #[test]
    fn install_scripts_are_read_without_extraction() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("pacman-install");
        let archive = build_package(dir.path(), Some("post_install() { rm -rf /; }\n"));

        let mut report = Report::default();
        assert!(scan_install_script(&archive, "sample", &mut report).unwrap());
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule, RuleId::DestructiveSystemOperation);
        assert_eq!(
            report.agent_input[0].content,
            "post_install() { rm -rf /; }\n"
        );
        assert!(!dir.path().join("sample").exists());

        let plain_dir = TempDir::new("pacman-plain");
        let plain = build_package(plain_dir.path(), None);
        assert!(!scan_install_script(&plain, "sample", &mut Report::default()).unwrap());
    }
}
