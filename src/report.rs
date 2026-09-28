//! Review results, the verdict derived from them, and their terminal rendering.

use std::env;
use std::fmt;
use std::io::{self, IsTerminal};
use std::process::ExitCode;

use crate::agent::{AgentReview, SourceFile, Status};
use crate::deps::Inventory;
use crate::error::Error;
use crate::osv::Audit;
use crate::rules::{RuleId, Scheme};
use crate::scan::{FileKind, Snapshot};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "low" => Some(Self::Low),
            _ => None,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
        }
    }

    const fn color(self) -> &'static str {
        match self {
            Self::High => "31;1",
            Self::Medium => "33;1",
            Self::Low => "36;1",
        }
    }
}

/// A reason the review cannot vouch for what it was asked to review. Any gap
/// makes the verdict `Incomplete`.
#[derive(Debug)]
pub enum Gap {
    Io(Error),
    Symlink(String),
    SpecialFile(String),
    NonUtf8Name(String),
    OversizedText(String),
    HashLimit(String),
    UnresolvedLfs(String),
    SensitiveWithheld(String),
    AgentInputTooLarge,
    NoReviewableFiles,
    Agent(Error),
    Dependency(String),
    Package(Error),
}

impl fmt::Display for Gap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) | Self::Package(error) => write!(f, "{error}"),
            Self::Symlink(path) => write!(f, "{path}: refusing to follow a symbolic link"),
            Self::SpecialFile(path) => write!(f, "{path}: not a regular file or directory"),
            Self::NonUtf8Name(path) => write!(f, "{path}: file name is not valid UTF-8"),
            Self::OversizedText(path) => {
                write!(f, "{path}: text file exceeds the 2 MiB review limit")
            }
            Self::HashLimit(path) => {
                write!(f, "{path}: file exceeds the 512 MiB integrity-hash limit")
            }
            Self::UnresolvedLfs(path) => write!(
                f,
                "{path}: Git LFS content is unresolved; refusing to review a pointer as source"
            ),
            Self::SensitiveWithheld(path) => write!(
                f,
                "{path}: withheld from the AI provider because it looks sensitive"
            ),
            Self::AgentInputTooLarge => {
                f.write_str("source exceeds the 256 KiB AI review input limit")
            }
            Self::NoReviewableFiles => {
                f.write_str("no readable text source files were available for review")
            }
            Self::Agent(error) => write!(f, "OpenCode review failed: {error}"),
            Self::Dependency(message) => f.write_str(message),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Clear,
    Findings,
    Incomplete,
    /// Nothing reviewable existed (a pacman transaction without scriptlets).
    Limited,
}

impl Verdict {
    pub fn exit_code(self) -> ExitCode {
        match self {
            Self::Clear | Self::Limited => ExitCode::SUCCESS,
            Self::Findings => ExitCode::from(1),
            Self::Incomplete => ExitCode::from(2),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalFinding {
    pub path: String,
    pub line: usize,
    pub rule: RuleId,
    pub excerpt: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkRequest {
    pub path: String,
    pub line: usize,
    pub scheme: Scheme,
    pub host: String,
}

#[derive(Debug, Default)]
pub struct Report {
    pub subject: String,
    pub snapshot: Snapshot,
    pub gaps: Vec<Gap>,
    pub text_files_reviewed: usize,
    pub findings: Vec<LocalFinding>,
    pub network: Vec<NetworkRequest>,
    pub agent_input: Vec<SourceFile>,
    pub agent_input_size: usize,
    pub agent_input_overflowed: bool,
    pub dependencies: Inventory,
    pub audit: Option<Audit>,
    pub agent: Option<AgentReview>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counts {
    high: usize,
    medium: usize,
    low: usize,
}

impl Counts {
    fn add(&mut self, severity: Severity) {
        match severity {
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
        }
    }

    const fn total(self) -> usize {
        self.high + self.medium + self.low
    }
}

impl Report {
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            ..Self::default()
        }
    }

    pub fn verdict(&self) -> Verdict {
        let agent_status = self.agent.as_ref().map(|review| review.status);

        if !self.gaps.is_empty() || agent_status == Some(Status::Inconclusive) {
            Verdict::Incomplete
        } else if !self.findings.is_empty()
            || self
                .audit
                .as_ref()
                .is_some_and(|audit| !audit.advisories.is_empty())
            || self.agent.as_ref().is_some_and(|review| {
                review.status == Status::Suspicious || !review.findings.is_empty()
            })
        {
            Verdict::Findings
        } else if self.text_files_reviewed == 0 && self.agent.is_none() {
            Verdict::Limited
        } else {
            Verdict::Clear
        }
    }

    /// Dependency advisories without a known severity count as medium.
    fn counts(&self) -> Counts {
        let mut counts = Counts::default();
        for finding in &self.findings {
            counts.add(finding.rule.severity());
        }
        for finding in self.agent.iter().flat_map(|review| &review.findings) {
            counts.add(finding.severity);
        }
        for advisory in self.audit.iter().flat_map(|audit| &audit.advisories) {
            counts.add(advisory.severity.unwrap_or(Severity::Medium));
        }
        counts
    }

    fn oversized_count(&self) -> usize {
        self.gaps
            .iter()
            .filter(|gap| matches!(gap, Gap::OversizedText(_)))
            .count()
    }

    fn withheld_count(&self) -> usize {
        self.gaps
            .iter()
            .filter(|gap| matches!(gap, Gap::SensitiveWithheld(_)))
            .count()
    }

    pub fn print(&self, show_hashes: bool) {
        let painter = Painter::for_stdout();
        let verdict = self.verdict();

        println!("Omarchy Guardian  ·  {}", self.subject);
        self.print_headline(verdict, painter);
        self.print_coverage(show_hashes, painter);
        self.print_inventory();
        self.print_agent_summary(painter);
        self.print_findings(verdict, painter);

        for gap in &self.gaps {
            eprintln!("  ! {gap}");
        }
        println!(
            "\n{}",
            match verdict {
                Verdict::Findings => {
                    "Recommendation: do not install or run this source until findings are resolved."
                }
                Verdict::Incomplete => "Recommendation: do not proceed; complete the review first.",
                Verdict::Limited => {
                    "Scope: package payloads were not inspected by this scriptlet-only review."
                }
                Verdict::Clear =>
                    "Scope: this is a heuristic source review, not a safety guarantee.",
            }
        );
    }

    fn print_headline(&self, verdict: Verdict, painter: Painter) {
        let counts = self.counts();
        let total = counts.total();
        let (headline, color) = match verdict {
            Verdict::Clear => ("✓ CLEAR — no known concerns found".to_string(), "32"),
            Verdict::Findings if counts.high > 0 => (
                format!("✗ HIGH RISK — {total} alert(s) across local and AI review"),
                "31;1",
            ),
            Verdict::Findings => (
                format!("! REVIEW REQUIRED — {total} alert(s) across local and AI review"),
                "33;1",
            ),
            Verdict::Incomplete => (
                "! INCOMPLETE — this scan is not a clean result".to_string(),
                "33;1",
            ),
            Verdict::Limited => (
                "· LIMITED REVIEW — no text install scripts were available".to_string(),
                "36;1",
            ),
        };
        println!("{}", painter.paint(&headline, color));

        if total > 0 {
            println!(
                "Alerts: {} high · {} medium · {} low",
                painter.paint(
                    &counts.high.to_string(),
                    if counts.high > 0 { "31;1" } else { "2" }
                ),
                painter.paint(
                    &counts.medium.to_string(),
                    if counts.medium > 0 { "33;1" } else { "2" }
                ),
                painter.paint(
                    &counts.low.to_string(),
                    if counts.low > 0 { "36;1" } else { "2" }
                ),
            );
        }
    }

    fn print_coverage(&self, show_hashes: bool, painter: Painter) {
        println!(
            "Coverage: {} text file(s) reviewed · {} binary file(s) hashed only · {} oversized text file(s) skipped",
            self.text_files_reviewed,
            self.snapshot.count(FileKind::Binary),
            self.oversized_count()
        );

        let files = self.snapshot.files();
        if !files.is_empty() {
            println!(
                "Integrity: SHA-256 manifest {} ({} file(s) hashed)",
                painter.paint(&self.snapshot.manifest_digest().to_string(), "36"),
                files.len(),
            );
            if show_hashes {
                println!("Per-file SHA-256:");
                for file in files {
                    let kind = if file.kind == FileKind::Text {
                        "reviewed-text"
                    } else {
                        "hash-only"
                    };
                    println!("  {}  {kind}  {}", file.sha256, file.path);
                }
            }
        }

        let withheld = self.withheld_count();
        if withheld > 0 {
            println!(
                "Privacy: {withheld} sensitive-looking file(s) withheld from the OpenCode provider"
            );
        }
    }

    fn print_inventory(&self) {
        if !self.network.is_empty() {
            let mut endpoints = self.network.clone();
            endpoints.sort();
            endpoints.dedup();
            println!("Network destinations observed: {}", endpoints.len());
            for endpoint in endpoints.iter().take(20) {
                println!(
                    "  {}:{} → {}://{}",
                    endpoint.path,
                    endpoint.line,
                    endpoint.scheme.as_str(),
                    endpoint.host
                );
            }
            if endpoints.len() > 20 {
                println!("  … and {} more endpoint(s)", endpoints.len() - 20);
            }
        }

        let lockfiles = self.dependencies.lockfile_count();
        if lockfiles == 0 {
            return;
        }
        let packages = self.dependencies.packages().len();
        if packages == 0 {
            println!("Dependencies: {lockfiles} lockfile(s) parsed; no registry packages found");
            return;
        }
        let (status, advisories) = match &self.audit {
            Some(audit) => ("checked against OSV", audit.advisories.len()),
            None => ("OSV audit incomplete", 0),
        };
        println!(
            "Dependencies: {packages} locked package/version(s) · {lockfiles} lockfile(s) · {status} · {advisories} known vulnerability advisory(ies)"
        );
    }

    fn print_agent_summary(&self, painter: Painter) {
        if self.agent_input_overflowed {
            println!("OpenCode review: not run — source exceeds the 256 KiB input limit");
        }
        if let Some(review) = &self.agent {
            let color = match review.status {
                Status::Clear => "32",
                Status::Suspicious => "31;1",
                Status::Inconclusive => "33;1",
            };
            println!(
                "OpenCode: {} — {}",
                painter.paint(review.status.label(), color),
                review.summary
            );
        }
    }

    fn print_findings(&self, verdict: Verdict, painter: Painter) {
        if self.findings.is_empty() {
            if verdict != Verdict::Limited {
                println!("Local checks: no matches");
            }
        } else {
            println!("\nLocal checks:");
            for finding in &self.findings {
                let severity = finding.rule.severity();
                println!(
                    "  [{}] {}:{} — {}",
                    painter.paint(severity.label(), severity.color()),
                    finding.path,
                    finding.line,
                    finding.rule.name()
                );
                println!("       {}", finding.rule.description());
                if !finding.excerpt.is_empty() {
                    println!("       {}", finding.excerpt);
                }
            }
        }

        if let Some(review) = self
            .agent
            .as_ref()
            .filter(|review| !review.findings.is_empty())
        {
            println!("\nOpenCode findings:");
            for finding in &review.findings {
                let line = finding
                    .line
                    .map(|line| format!(":{line}"))
                    .unwrap_or_default();
                println!(
                    "  [{}] {}{line} — {}",
                    painter.paint(finding.severity.label(), finding.severity.color()),
                    finding.file,
                    finding.title
                );
                println!("       {}", finding.reason);
            }
        }

        if let Some(audit) = self
            .audit
            .as_ref()
            .filter(|audit| !audit.advisories.is_empty())
        {
            println!("\nKnown dependency vulnerabilities:");
            for advisory in &audit.advisories {
                let (label, color) = advisory.severity.map_or(("UNRATED", "36;1"), |severity| {
                    (severity.label(), severity.color())
                });
                println!(
                    "  [{}] {}@{} — {} ({})",
                    painter.paint(label, color),
                    advisory.package,
                    advisory.version,
                    advisory.id,
                    advisory.lockfile
                );
                if let Some(summary) = &advisory.summary {
                    println!("       {summary}");
                }
            }
            if audit.truncated {
                println!("  … OSV reported more advisories than it returned in one page");
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Painter {
    enabled: bool,
}

impl Painter {
    fn for_stdout() -> Self {
        Self {
            enabled: io::stdout().is_terminal()
                && env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
                && env::var("TERM").is_ok_and(|term| term != "dumb"),
        }
    }

    fn paint(self, text: &str, color: &str) -> String {
        if self.enabled {
            format!("\x1b[{color}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Gap, Painter, Report, Severity, Verdict};
    use crate::agent::{AgentFinding, AgentReview, Status};
    use crate::osv::{Advisory, Audit};
    use crate::report::LocalFinding;
    use crate::rules::RuleId;

    fn review(status: Status) -> AgentReview {
        AgentReview {
            status,
            summary: "summary".into(),
            findings: Vec::new(),
        }
    }

    #[test]
    fn an_empty_scriptlet_review_is_limited() {
        assert_eq!(Report::default().verdict(), Verdict::Limited);
    }

    #[test]
    fn a_reviewed_tree_without_findings_is_clear() {
        let report = Report {
            text_files_reviewed: 1,
            agent: Some(review(Status::Clear)),
            ..Report::default()
        };
        assert_eq!(report.verdict(), Verdict::Clear);
    }

    #[test]
    fn gaps_and_inconclusive_reviews_outrank_findings() {
        let finding = LocalFinding {
            path: "a.sh".into(),
            line: 1,
            rule: RuleId::DownloadAndExecute,
            excerpt: String::new(),
        };

        let mut report = Report {
            text_files_reviewed: 1,
            findings: vec![finding],
            agent: Some(review(Status::Clear)),
            ..Report::default()
        };
        assert_eq!(report.verdict(), Verdict::Findings);

        report.agent = Some(review(Status::Inconclusive));
        assert_eq!(report.verdict(), Verdict::Incomplete);

        report.agent = Some(review(Status::Clear));
        report.gaps.push(Gap::NoReviewableFiles);
        assert_eq!(report.verdict(), Verdict::Incomplete);
    }

    #[test]
    fn agent_findings_and_advisories_are_findings() {
        let mut agent = review(Status::Clear);
        agent.findings.push(AgentFinding {
            severity: Severity::Low,
            file: "a".into(),
            line: None,
            title: "t".into(),
            reason: "r".into(),
        });
        let report = Report {
            text_files_reviewed: 1,
            agent: Some(agent),
            ..Report::default()
        };
        assert_eq!(report.verdict(), Verdict::Findings);

        let report = Report {
            text_files_reviewed: 1,
            agent: Some(review(Status::Clear)),
            audit: Some(Audit {
                advisories: vec![Advisory {
                    id: "GHSA-x".into(),
                    package: "p".into(),
                    version: "1".into(),
                    lockfile: "Cargo.lock".into(),
                    severity: None,
                    summary: None,
                }],
                truncated: false,
            }),
            ..Report::default()
        };
        assert_eq!(report.verdict(), Verdict::Findings);
        assert_eq!(report.counts().medium, 1);
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
