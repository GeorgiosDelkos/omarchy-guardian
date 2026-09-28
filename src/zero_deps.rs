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
