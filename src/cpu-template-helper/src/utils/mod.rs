// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::fmt::Display;
use std::fs::read_to_string;
use std::hash::Hash;
use std::path::{Path, PathBuf};

use vmm::cpu_config::templates::CustomCpuTemplate;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

pub const CPU_TEMPLATE_HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Trait for key of `HashMap`-based modifier.
///
/// This is a wrapper trait of some traits required for a key of `HashMap` modifier.
pub trait ModifierMapKey: Eq + PartialEq + Hash + Display + Clone {}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum UtilsError {
    /// Failed to operate file: {0}
    FileIo(#[from] std::io::Error),
    /// Failed to serialize/deserialize JSON file: {0}
    Serde(#[from] serde_json::Error),
}

pub fn load_cpu_template(path: &PathBuf) -> Result<CustomCpuTemplate, UtilsError> {
    let template_json = read_to_string(path)?;
    let template = serde_json::from_str(&template_json)?;
    Ok(template)
}

pub fn add_suffix(path: &Path, suffix: &str) -> PathBuf {
    // Extract the part of the filename before the extension.
    let mut new_file_name = OsString::from(path.file_stem().unwrap());

    // Push the suffix and the extension.
    new_file_name.push(suffix);
    if let Some(ext) = path.extension() {
        new_file_name.push(".");
        new_file_name.push(ext);
    }

    // Swap the file name.
    path.with_file_name(new_file_name)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    const SUFFIX: &str = "_suffix";

    #[derive(Debug, PartialEq, Eq, Hash, Clone)]
    pub struct MockModifierMapKey(pub u8);

    impl ModifierMapKey for MockModifierMapKey {}
    impl Display for MockModifierMapKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ID={:#x}", self.0)
        }
    }

    macro_rules! mock_modifier {
        ($key:expr, $value:expr) => {
            (
                MockModifierMapKey($key),
                RegisterValueFilter::<u8> {
                    filter: u8::MAX,
                    value: $value,
                },
            )
        };
        ($key:expr, $value:expr, $filter:expr) => {
            (
                MockModifierMapKey($key),
                RegisterValueFilter::<u8> {
                    filter: $filter,
                    value: $value,
                },
            )
        };
    }

    pub(crate) use mock_modifier;

    #[test]
    fn test_add_suffix_filename_only() {
        let path = PathBuf::from("file.ext");
        let expected = PathBuf::from(format!("file{SUFFIX}.ext"));
        assert_eq!(add_suffix(&path, SUFFIX), expected);
    }

    #[test]
    fn test_add_suffix_filename_without_ext() {
        let path = PathBuf::from("file_no_ext");
        let expected = PathBuf::from(format!("file_no_ext{SUFFIX}"));
        assert_eq!(add_suffix(&path, SUFFIX), expected);
    }

    #[test]
    fn test_add_suffix_rel_path() {
        let path = PathBuf::from("relative/path/to/file.ext");
        let expected = PathBuf::from(format!("relative/path/to/file{SUFFIX}.ext"));
        assert_eq!(add_suffix(&path, SUFFIX), expected);
    }

    #[test]
    fn test_add_suffix_abs_path() {
        let path = PathBuf::from("/absolute/path/to/file.ext");
        let expected = PathBuf::from(format!("/absolute/path/to/file{SUFFIX}.ext"));
        assert_eq!(add_suffix(&path, SUFFIX), expected);
    }
}
