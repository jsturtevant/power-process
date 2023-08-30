
use std::collections::BTreeMap;
use std::os::windows::prelude::OsStrExt;
use std::ffi::{OsStr, OsString};
use std::{fmt, cmp};

#[derive(Clone, Debug, Eq, PartialEq, Default, PartialOrd, Ord)]
#[doc(hidden)]
pub(crate) struct EnvKey {
    pub(crate) os_string: OsString,
    // This stores a UTF-16 encoded string to workaround the mismatch between
    // Rust's OsString (WTF-8) and the Windows API string type (UTF-16).
    // Normally converting on every API call is acceptable but here
    // `c::CompareStringOrdinal` will be called for every use of `==`.
    pub(crate) utf16: Vec<u16>,
}

impl EnvKey {
    pub (crate) fn new<T: Into<OsString>>(key: T) -> Self {
        EnvKey::from(key.into())
    }
}

// Environment variable keys should preserve their original case even though
// they are compared using a caseless string mapping.
impl From<OsString> for EnvKey {
    fn from(k: OsString) -> Self {
        EnvKey { utf16: k.encode_wide().collect(), os_string: k }
    }
}

impl From<EnvKey> for OsString {
    fn from(k: EnvKey) -> Self {
        k.os_string
    }
}

impl From<&OsStr> for EnvKey {
    fn from(k: &OsStr) -> Self {
        Self::from(k.to_os_string())
    }
}

impl AsRef<OsStr> for EnvKey {
    fn as_ref(&self) -> &OsStr {
        &self.os_string
    }
}

impl PartialEq<str> for EnvKey {
    fn eq(&self, other: &str) -> bool {
        if self.os_string.len() != other.len() {
            false
        } else {
            self.cmp(&EnvKey::new(other)) == cmp::Ordering::Equal
        }
    }
}

// Stores a set of changes to an environment
#[derive(Clone)]
pub struct CommandEnv {
    clear: bool,
    saw_path: bool,
    vars: BTreeMap<EnvKey, Option<OsString>>,
}

impl Default for CommandEnv {
    fn default() -> Self {
        CommandEnv { clear: false, saw_path: false, vars: Default::default() }
    }
}

impl fmt::Debug for CommandEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug_command_env = f.debug_struct("CommandEnv");
        debug_command_env.field("clear", &self.clear).field("vars", &self.vars);
        debug_command_env.finish()
    }
}

impl CommandEnv {
    // Capture the current environment with these changes applied
    pub(crate) fn capture(&self) -> BTreeMap<EnvKey, OsString> {
        let mut result = BTreeMap::<EnvKey, OsString>::new();
        if !self.clear {
            for (k, v) in std::env::vars_os() {
                result.insert(k.into(), v);
            }
        }
        for (k, maybe_v) in &self.vars {
            if let &Some(ref v) = maybe_v {
                result.insert(k.clone(), v.clone());
            } else {
                result.remove(k);
            }
        }
        result
    }

    pub fn is_unchanged(&self) -> bool {
        !self.clear && self.vars.is_empty()
    }

    pub(crate) fn capture_if_changed(&self) -> Option<BTreeMap<EnvKey, OsString>> {
        if self.is_unchanged() { None } else { Some(self.capture()) }
    }

    // The following functions build up changes
    pub fn set(&mut self, key: &OsStr, value: &OsStr) {
        let key = EnvKey::from(key);
        self.maybe_saw_path(&key);
        self.vars.insert(key, Some(value.to_owned()));
    }

    pub fn remove(&mut self, key: &OsStr) {
        let key = EnvKey::from(key);
        self.maybe_saw_path(&key);
        if self.clear {
            self.vars.remove(&key);
        } else {
            self.vars.insert(key, None);
        }
    }

    pub fn clear(&mut self) {
        self.clear = true;
        self.vars.clear();
    }

    pub fn have_changed_path(&self) -> bool {
        self.saw_path || self.clear
    }

    fn maybe_saw_path(&mut self, key: &EnvKey) {
        if !self.saw_path && key == "PATH" {
            self.saw_path = true;
        }
    }

    // pub fn iter(&self) -> CommandEnvs<'_> {
    //     let iter = self.vars.iter();
    //     CommandEnvs { iter }
    // }
}