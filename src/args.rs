//! The Windows command line is just a string
//! <https://docs.microsoft.com/en-us/archive/blogs/larryosterman/the-windows-command-line-is-just-a-string>
//!
//! This module implements the parsing necessary to turn that string into a list of arguments.

use crate::c;
use crate::path_ext::get_long_path;
use crate::windows::{ensure_no_nuls, to_u16s};

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::os::windows::prelude::*;
use std::path::Path;
use std::vec;

pub struct Args {
    parsed_args_list: vec::IntoIter<OsString>,
}

impl fmt::Debug for Args {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.parsed_args_list.as_slice().fmt(f)
    }
}

impl Iterator for Args {
    type Item = OsString;
    fn next(&mut self) -> Option<OsString> {
        self.parsed_args_list.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.parsed_args_list.size_hint()
    }
}

impl DoubleEndedIterator for Args {
    fn next_back(&mut self) -> Option<OsString> {
        self.parsed_args_list.next_back()
    }
}

impl ExactSizeIterator for Args {
    fn len(&self) -> usize {
        self.parsed_args_list.len()
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum Arg {
    /// Add quotes (if needed)
    Regular(OsString),
    /// Append raw string without quoting
    Raw(OsString),
}

enum Quote {
    // Every arg is quoted
    Always,
    // Whitespace and empty args are quoted
    Auto,
    // Arg appended without any changes (#29494)
    Never,
}

pub(crate) fn append_arg(cmd: &mut Vec<u16>, arg: &Arg, force_quotes: bool) -> io::Result<()> {
    let (arg, quote) = match arg {
        Arg::Regular(arg) => (
            arg,
            if force_quotes {
                Quote::Always
            } else {
                Quote::Auto
            },
        ),
        Arg::Raw(arg) => (arg, Quote::Never),
    };

    // If an argument has 0 characters then we need to quote it to ensure
    // that it actually gets passed through on the command line or otherwise
    // it will be dropped entirely when parsed on the other end.
    ensure_no_nuls(arg)?;
    let arg_bytes = arg.to_str().unwrap().as_bytes();
    let (quote, escape) = match quote {
        Quote::Always => (true, true),
        Quote::Auto => (
            arg_bytes.iter().any(|c| *c == b' ' || *c == b'\t') || arg_bytes.is_empty(),
            true,
        ),
        Quote::Never => (false, false),
    };
    if quote {
        cmd.push('"' as u16);
    }

    let mut backslashes: usize = 0;
    for x in arg.encode_wide() {
        if escape {
            if x == '\\' as u16 {
                backslashes += 1;
            } else {
                if x == '"' as u16 {
                    // Add n+1 backslashes to total 2n+1 before internal '"'.
                    cmd.extend((0..=backslashes).map(|_| '\\' as u16));
                }
                backslashes = 0;
            }
        }
        cmd.push(x);
    }

    if quote {
        // Add n backslashes to total 2n before ending '"'.
        cmd.extend((0..backslashes).map(|_| '\\' as u16));
        cmd.push('"' as u16);
    }
    Ok(())
}

pub(crate) fn make_bat_command_line(
    script: &[u16],
    args: &[Arg],
    force_quotes: bool,
) -> io::Result<Vec<u16>> {
    // Set the start of the command line to `cmd.exe /c "`
    // It is necessary to surround the command in an extra pair of quotes,
    // hence the trailing quote here. It will be closed after all arguments
    // have been added.
    let mut cmd: Vec<u16> = "cmd.exe /d /c \"".encode_utf16().collect();

    // Push the script name surrounded by its quote pair.
    cmd.push(b'"' as u16);
    // Windows file names cannot contain a `"` character or end with `\\`.
    // If the script name does then return an error.
    if script.contains(&(b'"' as u16)) || script.last() == Some(&(b'\\' as u16)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows file names may not contain `\"` or end with `\\`",
        ));
    }
    cmd.extend_from_slice(script.strip_suffix(&[0]).unwrap_or(script));
    cmd.push(b'"' as u16);

    // Append the arguments.
    // FIXME: This needs tests to ensure that the arguments are properly
    // reconstructed by the batch script by default.
    for arg in args {
        cmd.push(' ' as u16);
        // Make sure to always quote special command prompt characters, including:
        // * Characters `cmd /?` says require quotes.
        // * `%` for environment variables, as in `%TMP%`.
        // * `|<>` pipe/redirect characters.
        const SPECIAL: &[u8] = b"\t &()[]{}^=;!'+,`~%|<>";
        let force_quotes = match arg {
            Arg::Regular(arg) if !force_quotes => arg
                .to_str()
                .unwrap()
                .as_bytes()
                .iter()
                .any(|c| SPECIAL.contains(c)),
            _ => force_quotes,
        };
        append_arg(&mut cmd, arg, force_quotes)?;
    }

    // Close the quote we left opened earlier.
    cmd.push(b'"' as u16);

    Ok(cmd)
}

/// Takes a path and tries to return a non-verbatim path.
///
/// This is necessary because cmd.exe does not support verbatim paths.
pub(crate) fn to_user_path(path: &Path) -> io::Result<Vec<u16>> {
    from_wide_to_user_path(to_u16s(path)?)
}
pub(crate) fn from_wide_to_user_path(mut path: Vec<u16>) -> io::Result<Vec<u16>> {
    use crate::windows::fill_utf16_buf;
    use std::ptr;

    // UTF-16 encoded code points, used in parsing and building UTF-16 paths.
    // All of these are in the ASCII range so they can be cast directly to `u16`.
    const SEP: u16 = b'\\' as _;
    const QUERY: u16 = b'?' as _;
    const COLON: u16 = b':' as _;
    const U: u16 = b'U' as _;
    const N: u16 = b'N' as _;
    const C: u16 = b'C' as _;

    // Early return if the path is too long to remove the verbatim prefix.
    const LEGACY_MAX_PATH: usize = 260;
    if path.len() > LEGACY_MAX_PATH {
        return Ok(path);
    }

    match &path[..] {
        // `\\?\C:\...` => `C:\...`
        [SEP, SEP, QUERY, SEP, _, COLON, SEP, ..] => unsafe {
            let lpfilename = path[4..].as_ptr();
            fill_utf16_buf(
                |buffer, size| c::GetFullPathNameW(lpfilename, size, buffer, ptr::null_mut()),
                |full_path: &[u16]| {
                    if full_path == &path[4..path.len() - 1] {
                        let mut path: Vec<u16> = full_path.into();
                        path.push(0);
                        path
                    } else {
                        path
                    }
                },
            )
        },
        // `\\?\UNC\...` => `\\...`
        [SEP, SEP, QUERY, SEP, U, N, C, SEP, ..] => unsafe {
            // Change the `C` in `UNC\` to `\` so we can get a slice that starts with `\\`.
            path[6] = b'\\' as u16;
            let lpfilename = path[6..].as_ptr();
            fill_utf16_buf(
                |buffer, size| c::GetFullPathNameW(lpfilename, size, buffer, ptr::null_mut()),
                |full_path: &[u16]| {
                    if full_path == &path[6..path.len() - 1] {
                        let mut path: Vec<u16> = full_path.into();
                        path.push(0);
                        path
                    } else {
                        // Restore the 'C' in "UNC".
                        path[6] = b'C' as u16;
                        path
                    }
                },
            )
        },
        // For everything else, leave the path unchanged.
        _ => get_long_path(path, false),
    }
}
