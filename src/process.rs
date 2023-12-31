use crate::handle::Handle;
use crate::pipe::read2;
use crate::{c, command::StdioPipes};
use cvt::cvt;
use std::io::Error;
use std::{
    io,
    os::windows::{
        prelude::{AsHandle, AsRawHandle, BorrowedHandle},
        process::ExitStatusExt,
    },
    process::ExitStatus,
};

////////////////////////////////////////////////////////////////////////////////
// Processes
////////////////////////////////////////////////////////////////////////////////

/// A value representing a child process.
///
/// The lifetime of this value is linked to the lifetime of the actual
/// process - the Process destructor calls self.finish() which waits
/// for the process to terminate.
pub(crate) struct Process {
    pub(crate) process: Handle,
    pub(crate) main_thread_handle: Handle,
}


impl Process {
    pub fn kill(&mut self) -> io::Result<()> {
        let result = unsafe { c::TerminateProcess(self.process.as_raw_handle() as isize, 1) };
        if result == c::FALSE {
            let error = unsafe { c::GetLastError() };
            // TerminateProcess returns ERROR_ACCESS_DENIED if the process has already been
            // terminated (by us, or for any other reason). So check if the process was actually
            // terminated, and if so, do not return an error.
            if error != c::ERROR_ACCESS_DENIED || self.try_wait().is_err() {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
        }
        Ok(())
    }

    pub fn id(&self) -> u32 {
        unsafe { c::GetProcessId(self.process.as_raw_handle() as isize) as u32 }
    }

    pub fn main_thread_handle(&self) -> BorrowedHandle<'_> {
        self.main_thread_handle.as_handle()
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        unsafe {
            let res = c::WaitForSingleObject(self.process.as_raw_handle() as isize, c::INFINITE);
            if res != c::WAIT_OBJECT_0 {
                return Err(Error::last_os_error());
            }
            let mut status = 0;
            cvt(c::GetExitCodeProcess(
                self.process.as_raw_handle() as isize,
                &mut status,
            ))?;

            Ok(ExitStatus::from_raw(status))
        }
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        unsafe {
            match c::WaitForSingleObject(self.process.as_raw_handle() as isize, 0) {
                c::WAIT_OBJECT_0 => {}
                c::WAIT_TIMEOUT => {
                    return Ok(None);
                }
                _ => return Err(io::Error::last_os_error()),
            }
            let mut status = 0;
            cvt(c::GetExitCodeProcess(
                self.process.as_raw_handle() as isize,
                &mut status,
            ))?;
            Ok(Some(ExitStatus::from_raw(status)))
        }
    }

    pub fn handle(&self) -> BorrowedHandle {
        self.process.as_handle()
    }

    pub fn into_handle(self) -> Handle {
        self.process
    }
}

pub(crate) fn wait_with_output(
    mut process: Process,
    mut pipes: StdioPipes,
) -> io::Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    drop(pipes.stdin.take());

    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    match (pipes.stdout.take(), pipes.stderr.take()) {
        (None, None) => {}
        (Some(out), None) => {
            let res = out.read_to_end(&mut stdout);
            res.unwrap();
        }
        (None, Some(err)) => {
            let res = err.read_to_end(&mut stderr);
            res.unwrap();
        }
        (Some(out), Some(err)) => {
            let res = read2(out, &mut stdout, err, &mut stderr);
            res.unwrap();
        }
    }

    let status = process.wait()?;
    Ok((status, stdout, stderr))
}

pub trait ChildExt {
    fn main_thread_handle(&self) -> BorrowedHandle<'_>;
}


impl ChildExt for Process {
    fn main_thread_handle(&self) -> BorrowedHandle<'_> {
        self.main_thread_handle.as_handle()
    }
}