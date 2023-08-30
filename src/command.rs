#![allow(dead_code)]
use crate::args::{self, Arg};
use crate::env::{CommandEnv, EnvKey};
use crate::file::{open, OpenOptions};
use crate::handle::Handle;
use crate::path_ext;
use crate::pipe::{self, AnonPipe};
use crate::process::Process;
use crate::{c, windows};
use cvt::cvt;
use std::collections::BTreeMap;
use std::env::consts::{EXE_EXTENSION, EXE_SUFFIX};
use std::ffi::{c_void, OsStr, OsString};
use std::fs::File;
use std::os::windows::prelude::{
    AsRawHandle, FromRawHandle, IntoRawHandle, OsStrExt, OsStringExt, RawHandle,
};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Mutex;
use std::{env, fmt, io, mem, ptr};

pub enum Stdio {
    Inherit,
    Null,
    MakePipe,
    Pipe(AnonPipe),
    Handle(Handle),
}

pub struct StdioPipes {
    pub stdin: Option<AnonPipe>,
    pub stdout: Option<AnonPipe>,
    pub stderr: Option<AnonPipe>,
}

pub struct Command {
    program: OsString,
    args: Vec<Arg>,
    env: CommandEnv,
    cwd: Option<OsString>,
    flags: u32,
    detach: bool, // not currently exposed in std::process
    stdin: Option<Stdio>,
    stdout: Option<Stdio>,
    stderr: Option<Stdio>,
    force_quotes_enabled: bool,
}

impl Command {
    pub fn new(program: &OsStr) -> Command {
        Command {
            program: program.to_os_string(),
            args: Vec::new(),
            env: Default::default(),
            cwd: None,
            flags: 0,
            detach: false,
            stdin: None,
            stdout: None,
            stderr: None,
            force_quotes_enabled: false,
        }
    }

    pub fn arg(&mut self, arg: &OsStr) {
        self.args.push(Arg::Regular(arg.to_os_string()))
    }
    pub fn env<K, V>(&mut self, key: K, val: V) -> &mut Command
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.env_mut().set(key.as_ref(), val.as_ref());
        self
    }
    pub fn env_mut(&mut self) -> &mut CommandEnv {
        &mut self.env
    }
    pub fn cwd(&mut self, dir: &OsStr) {
        self.cwd = Some(dir.to_os_string())
    }
    pub fn stdin(&mut self, stdin: Stdio) {
        self.stdin = Some(stdin);
    }
    pub fn stdout(&mut self, stdout: Stdio) {
        self.stdout = Some(stdout);
    }
    pub fn stderr(&mut self, stderr: Stdio) {
        self.stderr = Some(stderr);
    }
    pub fn creation_flags(&mut self, flags: u32) {
        self.flags = flags;
    }

    pub fn force_quotes(&mut self, enabled: bool) {
        self.force_quotes_enabled = enabled;
    }

    pub fn raw_arg(&mut self, command_str_to_append: &OsStr) {
        self.args
            .push(Arg::Raw(command_str_to_append.to_os_string()))
    }

    pub fn get_program(&self) -> &OsStr {
        &self.program
    }

    pub fn get_args(&self) -> CommandArgs<'_> {
        let iter = self.args.iter();
        CommandArgs { iter }
    }

    // pub fn get_envs(&self) -> CommandEnvs<'_> {
    //     self.env.iter()
    // }

    pub fn get_current_dir(&self) -> Option<&Path> {
        self.cwd.as_ref().map(Path::new)
    }

    pub fn spawn(&mut self) -> io::Result<Process> {
        let (proc, _) = self.spawn_internal(Stdio::Inherit, true)?;
        Ok(proc)
    }

    pub fn spawn_internal(
        &mut self,
        default: Stdio,
        needs_stdin: bool,
    ) -> io::Result<(Process, StdioPipes)> {
        let maybe_env = self.env.capture_if_changed();

        let child_paths = if let Some(env) = maybe_env.as_ref() {
            env.get(&EnvKey::new("PATH")).map(|s| s.as_os_str())
        } else {
            None
        };
        let program = resolve_exe(&self.program, || env::var_os("PATH"), child_paths)?;
        // Case insensitive "ends_with" of UTF-16 encoded ".bat" or ".cmd"
        let is_batch_file = matches!(
            program.len().checked_sub(5).and_then(|i| program.get(i..)),
            Some([46, 98 | 66, 97 | 65, 116 | 84, 0] | [46, 99 | 67, 109 | 77, 100 | 68, 0])
        );
        let (program, mut cmd_str) = if is_batch_file {
            (
                command_prompt()?,
                args::make_bat_command_line(&program, &self.args, self.force_quotes_enabled)?,
            )
        } else {
            let cmd_str = make_command_line(&self.program, &self.args, self.force_quotes_enabled)?;
            (program, cmd_str)
        };
        cmd_str.push(0); // add null terminator

        // stolen from the libuv code.
        let mut flags = self.flags | c::CREATE_UNICODE_ENVIRONMENT;
        if self.detach {
            flags |= c::DETACHED_PROCESS | c::CREATE_NEW_PROCESS_GROUP;
        }

        let (envp, _data) = make_envp(maybe_env)?;
        let (dirp, _data) = make_dirp(self.cwd.as_ref())?;
        let mut pi = zeroed_process_information();

        // Prepare all stdio handles to be inherited by the child. This
        // currently involves duplicating any existing ones with the ability to
        // be inherited by child processes. Note, however, that once an
        // inheritable handle is created, *any* spawned child will inherit that
        // handle. We only want our own child to inherit this handle, so we wrap
        // the remaining portion of this spawn in a mutex.
        //
        // For more information, msdn also has an article about this race:
        // https://support.microsoft.com/kb/315939
        static CREATE_PROCESS_LOCK: Mutex<()> = Mutex::new(());

        let _guard = CREATE_PROCESS_LOCK.lock();

        let mut pipes = StdioPipes {
            stdin: None,
            stdout: None,
            stderr: None,
        };
        let null = Stdio::Null;
        let default_stdin = if needs_stdin { &default } else { &null };
        let stdin = self.stdin.as_ref().unwrap_or(default_stdin);
        let stdout = self.stdout.as_ref().unwrap_or(&default);
        let stderr = self.stderr.as_ref().unwrap_or(&default);
        let stdin = stdin.to_handle(c::STD_INPUT_HANDLE, &mut pipes.stdin)?;
        let stdout = stdout.to_handle(c::STD_OUTPUT_HANDLE, &mut pipes.stdout)?;
        let stderr = stderr.to_handle(c::STD_ERROR_HANDLE, &mut pipes.stderr)?;

        let mut si = zeroed_startupinfo();
        si.cb = mem::size_of::<c::STARTUPINFOW>() as c::DWORD;

        // If at least one of stdin, stdout or stderr are set (i.e. are non null)
        // then set the `hStd` fields in `STARTUPINFO`.
        // Otherwise skip this and allow the OS to apply its default behaviour.
        // This provides more consistent behaviour between Win7 and Win8+.
        let is_set = |stdio: &Handle| !stdio.as_raw_handle().is_null();
        if is_set(&stderr) || is_set(&stdout) || is_set(&stdin) {
            si.dwFlags |= c::STARTF_USESTDHANDLES;
            si.hStdInput = stdin.as_raw_handle();
            si.hStdOutput = stdout.as_raw_handle();
            si.hStdError = stderr.as_raw_handle();
        }

        unsafe {
            cvt(c::CreateProcessW(
                program.as_ptr(),
                cmd_str.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                c::TRUE,
                flags,
                envp,
                dirp,
                &si,
                &mut pi,
            ))
        }?;

        unsafe {
            Ok((
                Process {
                    handle: Handle::from_raw_handle(pi.hProcess as RawHandle),
                    main_thread_handle: Handle::from_raw_handle(pi.hThread as RawHandle),
                },
                pipes,
            ))
        }
    }

    pub fn output(&mut self) -> io::Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
        let (proc, pipes) = self.spawn_internal(Stdio::MakePipe, false)?;
        crate::process::wait_with_output(proc, pipes)
    }
}

fn std_name(stdio_id: c::DWORD) -> &'static str {
    match stdio_id {
        c::STD_INPUT_HANDLE => "stdin",
        c::STD_OUTPUT_HANDLE => "stdout",
        c::STD_ERROR_HANDLE => "stderr",
        _ => "unknown",
    }
}

impl From<AnonPipe> for Stdio {
    fn from(pipe: AnonPipe) -> Stdio {
        Stdio::Pipe(pipe)
    }
}

impl From<File> for Stdio {
    fn from(file: File) -> Stdio {
        unsafe { Stdio::Handle(Handle::from_raw_handle(file.as_raw_handle())) }
    }
}

impl Stdio {
    fn to_handle(&self, stdio_id: c::DWORD, pipe: &mut Option<AnonPipe>) -> io::Result<Handle> {
        match *self {
            Stdio::Inherit => match Stdio::get_handle(stdio_id) {
                Ok(io) => unsafe {
                    let io = Handle::from_raw_handle(io);
                    let ret = io.duplicate(0, true, c::DUPLICATE_SAME_ACCESS);
                    io.into_raw_handle();
                    ret
                },
                // If no stdio handle is available, then propagate the null value.
                Err(..) => unsafe { Ok(Handle::from_raw_handle(ptr::null_mut())) },
            },

            Stdio::MakePipe => {
                let ours_readable = stdio_id != c::STD_INPUT_HANDLE;
                let pipes = pipe::anon_pipe(ours_readable, true, std_name(stdio_id))?;
                *pipe = Some(pipes.ours);
                Ok(pipes.theirs.into_handle())
            }

            Stdio::Pipe(ref source) => {
                let ours_readable = stdio_id != c::STD_INPUT_HANDLE;
                pipe::spawn_pipe_relay(source, ours_readable, true, std_name(stdio_id))
                    .map(AnonPipe::into_handle)
            }

            Stdio::Handle(ref handle) => handle.duplicate(0, true, c::DUPLICATE_SAME_ACCESS),

            // Open up a reference to NUL with appropriate read/write
            // permissions as well as the ability to be inherited to child
            // processes (as this is about to be inherited).
            Stdio::Null => {
                let size = mem::size_of::<c::SECURITY_ATTRIBUTES>();
                let mut sa = c::SECURITY_ATTRIBUTES {
                    nLength: size as c::DWORD,
                    lpSecurityDescriptor: ptr::null_mut(),
                    bInheritHandle: 1,
                };
                let mut opts = OpenOptions::new();
                opts.read(stdio_id == c::STD_INPUT_HANDLE);
                opts.write(stdio_id != c::STD_INPUT_HANDLE);
                opts.security_attributes(&mut sa);
                let file = open(Path::new("NUL"), &opts)?;
                unsafe { Ok(Handle::from_raw_handle(file.as_raw_handle())) }
            }
        }
    }

    pub fn get_handle(handle_id: c::DWORD) -> io::Result<c::HANDLE> {
        let handle = unsafe { c::GetStdHandle(handle_id) };
        if handle == c::INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else if handle == -1 {
            Err(io::Error::from_raw_os_error(c::ERROR_INVALID_HANDLE as i32))
        } else {
            Ok(handle as RawHandle)
        }
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.program.fmt(f)?;
        for arg in &self.args {
            f.write_str(" ")?;
            match arg {
                Arg::Regular(s) => s.fmt(f),
                Arg::Raw(s) => f.write_str(&s.to_string_lossy()),
            }?;
        }
        Ok(())
    }
}

pub struct CommandArgs<'a> {
    iter: core::slice::Iter<'a, Arg>,
}

// Get `cmd.exe` for use with bat scripts, encoded as a UTF-16 string.
fn command_prompt() -> io::Result<Vec<u16>> {
    let mut system: Vec<u16> = windows::fill_utf16_buf(
        |buf, size| unsafe { c::GetSystemDirectoryW(buf, size) },
        |buf| buf.into(),
    )?;
    system.extend("\\cmd.exe".encode_utf16().chain([0]));
    Ok(system)
}

// Produces a wide string *without terminating null*; returns an error if
// `prog` or any of the `args` contain a nul.
fn make_command_line(argv0: &OsStr, args: &[Arg], force_quotes: bool) -> io::Result<Vec<u16>> {
    // Encode the command and arguments in a command line string such
    // that the spawned process may recover them using CommandLineToArgvW.
    let mut cmd: Vec<u16> = Vec::new();

    // Always quote the program name so CreateProcess to avoid ambiguity when
    // the child process parses its arguments.
    // Note that quotes aren't escaped here because they can't be used in arg0.
    // But that's ok because file paths can't contain quotes.
    cmd.push(b'"' as u16);
    cmd.extend(argv0.encode_wide());
    cmd.push(b'"' as u16);

    for arg in args {
        cmd.push(' ' as u16);
        args::append_arg(&mut cmd, arg, force_quotes)?;
    }
    Ok(cmd)
}

fn zeroed_startupinfo() -> c::STARTUPINFOW {
    c::STARTUPINFOW {
        cb: 0,
        lpReserved: ptr::null_mut(),
        lpDesktop: ptr::null_mut(),
        lpTitle: ptr::null_mut(),
        dwX: 0,
        dwY: 0,
        dwXSize: 0,
        dwYSize: 0,
        dwXCountChars: 0,
        dwYCountChars: 0,
        dwFillAttribute: 0,
        dwFlags: 0,
        wShowWindow: 0,
        cbReserved2: 0,
        lpReserved2: ptr::null_mut(),
        hStdInput: ptr::null_mut(),
        hStdOutput: ptr::null_mut(),
        hStdError: ptr::null_mut(),
    }
}

fn zeroed_process_information() -> c::PROCESS_INFORMATION {
    c::PROCESS_INFORMATION {
        hProcess: ptr::null_mut(),
        hThread: ptr::null_mut(),
        dwProcessId: 0,
        dwThreadId: 0,
    }
}

pub(crate) fn ensure_no_nuls<T: AsRef<OsStr>>(str: T) -> io::Result<T> {
    if str.as_ref().encode_wide().any(|b| b == 0) {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "nul byte found in provided data",
        ))
    } else {
        Ok(str)
    }
}

fn make_envp(maybe_env: Option<BTreeMap<EnvKey, OsString>>) -> io::Result<(*mut c_void, Vec<u16>)> {
    // On Windows we pass an "environment block" which is not a char**, but
    // rather a concatenation of null-terminated k=v\0 sequences, with a final
    // \0 to terminate.
    if let Some(env) = maybe_env {
        let mut blk = Vec::new();

        // If there are no environment variables to set then signal this by
        // pushing a null.
        if env.is_empty() {
            blk.push(0);
        }

        for (k, v) in env {
            ensure_no_nuls(k.os_string)?;
            blk.extend(k.utf16);
            blk.push('=' as u16);
            blk.extend(ensure_no_nuls(v)?.encode_wide());
            blk.push(0);
        }
        blk.push(0);
        Ok((blk.as_mut_ptr() as *mut c_void, blk))
    } else {
        Ok((ptr::null_mut(), Vec::new()))
    }
}

fn make_dirp(d: Option<&OsString>) -> io::Result<(*const u16, Vec<u16>)> {
    match d {
        Some(dir) => {
            let mut dir_str: Vec<u16> = ensure_no_nuls(dir)?.encode_wide().collect();
            dir_str.push(0);
            Ok((dir_str.as_ptr(), dir_str))
        }
        None => Ok((ptr::null(), Vec::new())),
    }
}

// Resolve `exe_path` to the executable name.
//
// * If the path is simply a file name then use the paths given by `search_paths` to find the executable.
// * Otherwise use the `exe_path` as given.
//
// This function may also append `.exe` to the name. The rationale for doing so is as follows:
//
// It is a very strong convention that Windows executables have the `exe` extension.
// In Rust, it is common to omit this extension.
// Therefore this functions first assumes `.exe` was intended.
// It falls back to the plain file name if a full path is given and the extension is omitted
// or if only a file name is given and it already contains an extension.
fn resolve_exe(
    exe_path: &OsStr,
    parent_paths: impl FnOnce() -> Option<OsString>,
    child_paths: Option<&OsStr>,
) -> io::Result<Vec<u16>> {
    // Early return if there is no filename.
    if exe_path.is_empty() || path_ext::has_trailing_slash(exe_path) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "program path has no file name",
        ));
    }
    // Test if the file name has the `exe` extension.
    // This does a case-insensitive `ends_with`.
    let has_exe_suffix = if exe_path.len() >= EXE_SUFFIX.len() {
        exe_path.to_str().unwrap().as_bytes()[exe_path.len() - EXE_SUFFIX.len()..]
            .eq_ignore_ascii_case(EXE_SUFFIX.as_bytes())
    } else {
        false
    };

    // If `exe_path` is an absolute path or a sub-path then don't search `PATH` for it.
    if !path_ext::is_file_name(exe_path) {
        if has_exe_suffix {
            // The application name is a path to a `.exe` file.
            // Let `CreateProcessW` figure out if it exists or not.
            return args::to_user_path(Path::new(exe_path));
        }
        let mut path = PathBuf::from(exe_path);

        // Append `.exe` if not already there.
        path = path_ext::append_suffix(path, EXE_SUFFIX.as_ref());
        if let Some(path) = program_exists(&path) {
            return Ok(path);
        } else {
            // It's ok to use `set_extension` here because the intent is to
            // remove the extension that was just added.
            path.set_extension("");
            return args::to_user_path(&path);
        }
    } else {
        ensure_no_nuls(exe_path)?;
        // From the `CreateProcessW` docs:
        // > If the file name does not contain an extension, .exe is appended.
        // Note that this rule only applies when searching paths.
        let has_extension = exe_path.to_str().unwrap().as_bytes().contains(&b'.');

        // Search the directories given by `search_paths`.
        let result = search_paths(parent_paths, child_paths, |mut path| {
            path.push(exe_path);
            if !has_extension {
                path.set_extension(EXE_EXTENSION);
            }
            program_exists(&path)
        });
        if let Some(path) = result {
            return Ok(path);
        }
    }
    // If we get here then the executable cannot be found.
    Err(io::Error::new(io::ErrorKind::NotFound, "program not found"))
}

// Calls `f` for every path that should be used to find an executable.
// Returns once `f` returns the path to an executable or all paths have been searched.
fn search_paths<Paths, Exists>(
    parent_paths: Paths,
    child_paths: Option<&OsStr>,
    mut exists: Exists,
) -> Option<Vec<u16>>
where
    Paths: FnOnce() -> Option<OsString>,
    Exists: FnMut(PathBuf) -> Option<Vec<u16>>,
{
    // 1. Child paths
    // This is for consistency with Rust's historic behaviour.
    if let Some(paths) = child_paths {
        for path in env::split_paths(paths).filter(|p| !p.as_os_str().is_empty()) {
            if let Some(path) = exists(path) {
                return Some(path);
            }
        }
    }

    // 2. Application path
    if let Ok(mut app_path) = env::current_exe() {
        app_path.pop();
        if let Some(path) = exists(app_path) {
            return Some(path);
        }
    }

    // 3 & 4. System paths
    // SAFETY: This uses `fill_utf16_buf` to safely call the OS functions.
    unsafe {
        if let Ok(Some(path)) = windows::fill_utf16_buf(
            |buf, size| c::GetSystemDirectoryW(buf, size),
            |buf| exists(PathBuf::from(OsString::from_wide(buf))),
        ) {
            return Some(path);
        }
        #[cfg(not(target_vendor = "uwp"))]
        {
            if let Ok(Some(path)) = windows::fill_utf16_buf(
                |buf, size| c::GetWindowsDirectoryW(buf, size),
                |buf| exists(PathBuf::from(OsString::from_wide(buf))),
            ) {
                return Some(path);
            }
        }
    }

    // 5. Parent paths
    if let Some(parent_paths) = parent_paths() {
        for path in env::split_paths(&parent_paths).filter(|p| !p.as_os_str().is_empty()) {
            if let Some(path) = exists(path) {
                return Some(path);
            }
        }
    }
    None
}

/// Check if a file exists without following symlinks.
fn program_exists(path: &Path) -> Option<Vec<u16>> {
    unsafe {
        let path = args::to_user_path(path).ok()?;
        // Getting attributes using `GetFileAttributesW` does not follow symlinks
        // and it will almost always be successful if the link exists.
        // There are some exceptions for special system files (e.g. the pagefile)
        // but these are not executable.
        if c::GetFileAttributesW(path.as_ptr()) == c::INVALID_FILE_ATTRIBUTES {
            None
        } else {
            Some(path)
        }
    }
}
