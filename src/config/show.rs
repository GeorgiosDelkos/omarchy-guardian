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
        &settings.user_path().map_or_else(
            || "(no HOME)".to_string(),
            |path| path.display().to_string(),
        ),
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

        let _ = writeln!(
            text,
            "\n[{}]  {scope} · profile {}",
            class.name(),
            settings.profile_for(*class).name()
        );
        for knob in KNOBS {
            let value = match knob {
                "ai" => policy.ai.name().to_string(),
                "on_findings" => policy.on_findings.name().to_string(),
                "on_ai_suspicious" => policy.on_ai_suspicious.name().to_string(),
                "thinking" => policy.thinking.name().to_string(),
                "model" => policy
                    .model
                    .clone()
                    .unwrap_or_else(|| "(agent default)".into()),
                "timeout_secs" => policy.timeout_secs().to_string(),
                "confirm" => policy.confirm.to_string(),
                other => format!("(unknown knob {other})"),
            };
            let _ = writeln!(
                text,
                "  {knob:<17} {value:<17} ({})",
                resolved.origin(knob).name()
            );
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{render_check, render_show};
    use crate::config::Settings;
    use crate::config::model::SourceClass;
    use crate::test_support::TempDir;

    #[expect(
        clippy::unnecessary_wraps,
        reason = "must match the `Verify` callback signature `Settings::load_from` expects"
    )]
    fn secure(_: &Path) -> Result<(), String> {
        Ok(())
    }

    #[test]
    fn show_lists_values_origins_and_ignored_user_values() {
        let dir = TempDir::new("show");
        let system = dir.path().join("system.toml");
        let user = dir.path().join("user.toml");
        fs::write(&system, "[class.official]\nthinking = \"medium\"\n").unwrap();
        fs::write(
            &user,
            "[class.official]\nai = \"off\"\n[class.aur]\nthinking = \"max\"\n",
        )
        .unwrap();
        let settings = Settings::load_from(&system, Some(&user), &secure);

        let text = render_show(&settings, &[SourceClass::Official, SourceClass::Aur]);

        assert!(text.contains("[official]  enforced by the pacman hook"));
        assert!(text.contains("thinking          medium            (system)"));
        assert!(text.contains("ai = off ignored (user file)"));
        assert!(text.contains("[aur]"));
        assert!(text.contains("thinking          max               (user)"));
        assert!(
            text.contains(
                "agent             default model · max (provider default) · timeout 300s · input 256 KiB"
            )
        );
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
