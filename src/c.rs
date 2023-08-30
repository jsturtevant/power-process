#![allow(nonstandard_style)]
#![cfg_attr(test, allow(dead_code))]

use libc::c_void;
pub use windows_sys::Win32::Foundation::{
    RtlNtStatusToDosError, SetLastError, BOOL, DUPLICATE_HANDLE_OPTIONS, DUPLICATE_SAME_ACCESS,
    ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, ERROR_INSUFFICIENT_BUFFER,
    ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_IO_PENDING, ERROR_SUCCESS, FALSE,
    GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, STATUS_END_OF_FILE, STATUS_PENDING, TRUE,
    WAIT_OBJECT_0, WAIT_TIMEOUT, WIN32_ERROR,
};
pub use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};
pub use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
pub use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileAttributesW, GetFullPathNameW, CREATE_ALWAYS, CREATE_NEW,
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED,
    FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
    INVALID_FILE_ATTRIBUTES, OPEN_ALWAYS, OPEN_EXISTING, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND,
    SECURITY_SQOS_PRESENT, TRUNCATE_EXISTING,
};
pub use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
pub use windows_sys::Win32::System::Environment::GetCommandLineW;
pub use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
pub use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
pub use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
pub use windows_sys::Win32::System::Threading::TerminateProcess;
pub use windows_sys::Win32::System::Threading::{
    CreateEventW, CreateProcessW, GetCurrentProcessId, GetExitCodeProcess, GetProcessId, SleepEx,
    WaitForSingleObject, CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS,
    INFINITE, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};
pub use windows_sys::Win32::System::IO::CancelIo;

use core::ffi::NonZero_c_ulong;
use std::ffi::c_longlong;
use std::ffi::c_ulong;

pub type LPSECURITY_ATTRIBUTES = *mut SECURITY_ATTRIBUTES;
pub type NTSTATUS = i32;
pub type DWORD = c_ulong;
pub type ULONG = c_ulong;
pub type NonZeroDWORD = NonZero_c_ulong;
pub type LARGE_INTEGER = c_longlong;

pub use std::io::Error;
use std::os::windows::prelude::AsRawHandle;
use std::os::windows::prelude::BorrowedHandle;
pub use std::os::windows::raw::HANDLE;
use std::ptr;
#[repr(C)]
pub struct OVERLAPPED {
    pub Internal: usize,
    pub InternalHigh: usize,
    pub Anonymous: OVERLAPPED_0,
    pub hEvent: HANDLE,
}
impl ::core::marker::Copy for OVERLAPPED {}
impl ::core::clone::Clone for OVERLAPPED {
    fn clone(&self) -> Self {
        *self
    }
}

#[repr(C)]
pub union OVERLAPPED_0 {
    pub Anonymous: OVERLAPPED_0_0,
    pub Pointer: *mut ::core::ffi::c_void,
}
impl ::core::marker::Copy for OVERLAPPED_0 {}
impl ::core::clone::Clone for OVERLAPPED_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct OVERLAPPED_0_0 {
    pub Offset: u32,
    pub OffsetHigh: u32,
}
impl ::core::marker::Copy for OVERLAPPED_0_0 {}
impl ::core::clone::Clone for OVERLAPPED_0_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct IO_STATUS_BLOCK {
    pub Anonymous: IO_STATUS_BLOCK_0,
    pub Information: usize,
}
impl ::core::marker::Copy for IO_STATUS_BLOCK {}
impl ::core::clone::Clone for IO_STATUS_BLOCK {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union IO_STATUS_BLOCK_0 {
    pub Status: NTSTATUS,
    pub Pointer: *mut ::core::ffi::c_void,
}
impl ::core::marker::Copy for IO_STATUS_BLOCK_0 {}
impl ::core::clone::Clone for IO_STATUS_BLOCK_0 {
    fn clone(&self) -> Self {
        *self
    }
}

impl IO_STATUS_BLOCK {
    pub const PENDING: Self = IO_STATUS_BLOCK {
        Anonymous: IO_STATUS_BLOCK_0 {
            Status: STATUS_PENDING,
        },
        Information: 0,
    };
    pub fn status(&self) -> NTSTATUS {
        // SAFETY: If `self.Anonymous.Status` was set then this is obviously safe.
        // If `self.Anonymous.Pointer` was set then this is the equivalent to converting
        // the pointer to an integer, which is also safe.
        // Currently the only safe way to construct `IO_STATUS_BLOCK` outside of
        // this module is to call the `default` method, which sets the `Status`.
        unsafe { self.Anonymous.Status }
    }
}

pub unsafe extern "system" fn ReadFileEx(
    hFile: BorrowedHandle<'_>,
    lpBuffer: *mut ::core::ffi::c_void,
    nNumberOfBytesToRead: u32,
    lpOverlapped: *mut OVERLAPPED,
    lpCompletionRoutine: LPOVERLAPPED_COMPLETION_ROUTINE,
) -> BOOL {
    sys::ReadFileEx(
        hFile.as_raw_handle(),
        lpBuffer,
        nNumberOfBytesToRead,
        lpOverlapped,
        lpCompletionRoutine,
    )
}

pub unsafe extern "system" fn WriteFileEx(
    hFile: BorrowedHandle<'_>,
    lpBuffer: *mut ::core::ffi::c_void,
    nNumberOfBytesToWrite: u32,
    lpOverlapped: *mut OVERLAPPED,
    lpCompletionRoutine: LPOVERLAPPED_COMPLETION_ROUTINE,
) -> BOOL {
    sys::WriteFileEx(
        hFile.as_raw_handle(),
        lpBuffer.cast::<u8>(),
        nNumberOfBytesToWrite,
        lpOverlapped,
        lpCompletionRoutine,
    )
}

pub unsafe fn NtWriteFile(
    filehandle: BorrowedHandle<'_>,
    event: HANDLE,
    apcroutine: PIO_APC_ROUTINE,
    apccontext: *mut c_void,
    iostatusblock: &mut IO_STATUS_BLOCK,
    buffer: *const u8,
    length: ULONG,
    byteoffset: Option<&LARGE_INTEGER>,
    key: Option<&ULONG>,
) -> NTSTATUS {
    sys::NtWriteFile(
        filehandle.as_raw_handle(),
        event,
        apcroutine,
        apccontext,
        iostatusblock,
        buffer.cast::<c_void>(),
        length,
        byteoffset.map(|o| o as *const i64).unwrap_or(ptr::null()),
        key.map(|k| k as *const u32).unwrap_or(ptr::null()),
    )
}

#[link(name = "kernel32")]
extern "system" {
    pub fn GetOverlappedResult(
        hfile: HANDLE,
        lpoverlapped: *const OVERLAPPED,
        lpnumberofbytestransferred: *mut u32,
        bwait: BOOL,
    ) -> BOOL;
}

pub unsafe fn NtReadFile(
    filehandle: BorrowedHandle<'_>,
    event: HANDLE,
    apcroutine: PIO_APC_ROUTINE,
    apccontext: *mut c_void,
    iostatusblock: &mut IO_STATUS_BLOCK,
    buffer: *mut std::mem::MaybeUninit<u8>,
    length: ULONG,
    byteoffset: Option<&LARGE_INTEGER>,
    key: Option<&ULONG>,
) -> NTSTATUS {
    sys::NtReadFile(
        filehandle.as_raw_handle(),
        event,
        apcroutine,
        apccontext,
        iostatusblock,
        buffer.cast::<c_void>(),
        length,
        byteoffset.map(|o| o as *const i64).unwrap_or(ptr::null()),
        key.map(|k| k as *const u32).unwrap_or(ptr::null()),
    )
}

mod sys {
    use super::*;
    #[link(name = "kernel32")]
    extern "system" {
        pub fn ReadFileEx(
            hfile: HANDLE,
            lpbuffer: *mut ::core::ffi::c_void,
            nnumberofbytestoread: u32,
            lpoverlapped: *mut OVERLAPPED,
            lpcompletionroutine: LPOVERLAPPED_COMPLETION_ROUTINE,
        ) -> BOOL;

        pub fn WriteFileEx(
            hfile: HANDLE,
            lpbuffer: *const u8,
            nnumberofbytestowrite: u32,
            lpoverlapped: *mut OVERLAPPED,
            lpcompletionroutine: LPOVERLAPPED_COMPLETION_ROUTINE,
        ) -> BOOL;
    }

    #[link(name = "ntdll")]
    extern "system" {
        pub fn NtWriteFile(
            filehandle: HANDLE,
            event: HANDLE,
            apcroutine: PIO_APC_ROUTINE,
            apccontext: *const ::core::ffi::c_void,
            iostatusblock: *mut IO_STATUS_BLOCK,
            buffer: *const ::core::ffi::c_void,
            length: u32,
            byteoffset: *const i64,
            key: *const u32,
        ) -> NTSTATUS;

        pub fn NtReadFile(
            filehandle: HANDLE,
            event: HANDLE,
            apcroutine: PIO_APC_ROUTINE,
            apccontext: *const ::core::ffi::c_void,
            iostatusblock: *mut IO_STATUS_BLOCK,
            buffer: *mut ::core::ffi::c_void,
            length: u32,
            byteoffset: *const i64,
            key: *const u32,
        ) -> NTSTATUS;
    }
}

pub use windows_sys::Win32::Foundation::GetLastError;
pub type LPVOID = *mut c_void;
pub type LPOVERLAPPED = *mut OVERLAPPED;
pub type LPOVERLAPPED_COMPLETION_ROUTINE = ::core::option::Option<
    unsafe extern "system" fn(
        dwerrorcode: u32,
        dwnumberofbytestransfered: u32,
        lpoverlapped: *mut OVERLAPPED,
    ) -> (),
>;

// Equivalent to the `NT_SUCCESS` C preprocessor macro.
// See: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values
pub fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}
pub type BOOLEAN = u8;
#[link(name = "advapi32")]
extern "system" {
    #[link_name = "SystemFunction036"]
    pub fn RtlGenRandom(randombuffer: *mut ::core::ffi::c_void, randombufferlength: u32)
        -> BOOLEAN;
}

pub type PIO_APC_ROUTINE = ::core::option::Option<
    unsafe extern "system" fn(
        apccontext: *const ::core::ffi::c_void,
        iostatusblock: *const IO_STATUS_BLOCK,
        reserved: u32,
    ) -> (),
>;

#[link(name = "kernel32")]
extern "system" {
    pub fn WaitForMultipleObjects(
        ncount: u32,
        lphandles: *const HANDLE,
        bwaitall: BOOL,
        dwmilliseconds: u32,
    ) -> WIN32_ERROR;
}

#[link(name = "kernel32")]
extern "system" {
    pub fn ReadFile(
        hfile: HANDLE,
        lpbuffer: *mut ::core::ffi::c_void,
        nnumberofbytestoread: u32,
        lpnumberofbytesread: *mut u32,
        lpoverlapped: *mut OVERLAPPED,
    ) -> BOOL;
}

#[link(name = "kernel32")]
extern "system" {
    pub fn DuplicateHandle(
        hsourceprocesshandle: HANDLE,
        hsourcehandle: HANDLE,
        htargetprocesshandle: HANDLE,
        lptargethandle: *mut HANDLE,
        dwdesiredaccess: u32,
        binherithandle: BOOL,
        dwoptions: DUPLICATE_HANDLE_OPTIONS,
    ) -> BOOL;
}

#[link(name = "kernel32")]
extern "system" {
    pub fn GetCurrentProcess() -> HANDLE;
}
