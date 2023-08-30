use crate::c;
use cvt::cvt;
use std::cmp;
use std::io::{self, BorrowedCursor, ErrorKind, IoSlice, IoSliceMut, Read};
use std::mem;
use std::os::windows::io::{
    AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle,
};
use std::ptr;

/// An owned container for `HANDLE` object, closing them on Drop.
///
/// All methods are inherited through a `Deref` impl to `RawHandle`
pub struct Handle(pub OwnedHandle);

impl Handle {
    pub fn new_event(manual: bool, init: bool) -> io::Result<Handle> {
        unsafe {
            let event = c::CreateEventW(
                ptr::null_mut(),
                manual as c::BOOL,
                init as c::BOOL,
                ptr::null(),
            );
            if event == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(Handle::from_raw_handle(event as RawHandle))
            }
        }
    }
}

/// A trait for viewing representations from std types
#[doc(hidden)]
pub trait AsInner<Inner: ?Sized> {
    fn as_inner(&self) -> &Inner;
}

/// A trait for viewing representations from std types
#[doc(hidden)]
pub trait AsInnerMut<Inner: ?Sized> {
    fn as_inner_mut(&mut self) -> &mut Inner;
}

impl AsInner<OwnedHandle> for Handle {
    #[inline]
    fn as_inner(&self) -> &OwnedHandle {
        &self.0
    }
}

/// A trait for extracting representations from std types
#[doc(hidden)]
pub trait IntoInner<Inner> {
    fn into_inner(self) -> Inner;
}

/// A trait for creating std types from internal representations
#[doc(hidden)]
pub trait FromInner<Inner> {
    fn from_inner(inner: Inner) -> Self;
}

impl IntoInner<OwnedHandle> for Handle {
    fn into_inner(self) -> OwnedHandle {
        self.0
    }
}

impl FromInner<OwnedHandle> for Handle {
    fn from_inner(file_desc: OwnedHandle) -> Self {
        Self(file_desc)
    }
}

impl AsHandle for Handle {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.0.as_handle()
    }
}

impl AsRawHandle for Handle {
    fn as_raw_handle(&self) -> RawHandle {
        self.0.as_raw_handle()
    }
}

impl IntoRawHandle for Handle {
    fn into_raw_handle(self) -> RawHandle {
        self.0.into_raw_handle()
    }
}

impl FromRawHandle for Handle {
    unsafe fn from_raw_handle(raw_handle: RawHandle) -> Self {
        Self(FromRawHandle::from_raw_handle(raw_handle))
    }
}
pub(crate) fn default_write_vectored<F>(write: F, bufs: &[IoSlice<'_>]) -> io::Result<usize>
where
    F: FnOnce(&[u8]) -> io::Result<usize>,
{
    let buf = bufs
        .iter()
        .find(|b| !b.is_empty())
        .map_or(&[][..], |b| &**b);
    write(buf)
}

pub(crate) fn default_read_vectored<F>(read: F, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize>
where
    F: FnOnce(&mut [u8]) -> io::Result<usize>,
{
    let buf = bufs
        .iter_mut()
        .find(|b| !b.is_empty())
        .map_or(&mut [][..], |b| &mut **b);
    read(buf)
}

impl Handle {
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let res = unsafe { self.synchronous_read(buf.as_mut_ptr().cast(), buf.len(), None) };

        match res {
            Ok(read) => Ok(read as usize),

            // The special treatment of BrokenPipe is to deal with Windows
            // pipe semantics, which yields this error when *reading* from
            // a pipe after the other end has closed; we interpret that as
            // EOF on the pipe.
            Err(ref e) if e.kind() == ErrorKind::BrokenPipe => Ok(0),

            Err(e) => Err(e),
        }
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        default_read_vectored(|buf| self.read(buf), bufs)
    }

    #[inline]
    pub fn is_read_vectored(&self) -> bool {
        false
    }

    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let res =
            unsafe { self.synchronous_read(buf.as_mut_ptr().cast(), buf.len(), Some(offset)) };

        match res {
            Ok(read) => Ok(read as usize),
            Err(ref e) if e.raw_os_error() == Some(c::ERROR_HANDLE_EOF as i32) => Ok(0),
            Err(e) => Err(e),
        }
    }

    pub fn read_buf(&self, mut cursor: BorrowedCursor<'_>) -> io::Result<()> {
        let res =
            unsafe { self.synchronous_read(cursor.as_mut().as_mut_ptr(), cursor.capacity(), None) };

        match res {
            Ok(read) => {
                // Safety: `read` bytes were written to the initialized portion of the buffer
                unsafe {
                    cursor.advance(read as usize);
                }
                Ok(())
            }

            // The special treatment of BrokenPipe is to deal with Windows
            // pipe semantics, which yields this error when *reading* from
            // a pipe after the other end has closed; we interpret that as
            // EOF on the pipe.
            Err(ref e) if e.kind() == ErrorKind::BrokenPipe => Ok(()),

            Err(e) => Err(e),
        }
    }

    pub unsafe fn read_overlapped(
        &self,
        buf: &mut [u8],
        overlapped: *mut c::OVERLAPPED,
    ) -> io::Result<Option<usize>> {
        let len = cmp::min(buf.len(), <c::DWORD>::MAX as usize) as c::DWORD;
        let mut amt = 0;
        let res = cvt(c::ReadFile(
            self.as_raw_handle(),
            buf.as_ptr() as c::LPVOID,
            len,
            &mut amt,
            overlapped,
        ));
        match res {
            Ok(_) => Ok(Some(amt as usize)),
            Err(e) => {
                if e.raw_os_error() == Some(c::ERROR_IO_PENDING as i32) {
                    Ok(None)
                } else if e.raw_os_error() == Some(c::ERROR_BROKEN_PIPE as i32) {
                    Ok(Some(0))
                } else {
                    Err(e)
                }
            }
        }
    }

    pub fn overlapped_result(
        &self,
        overlapped: *mut c::OVERLAPPED,
        wait: bool,
    ) -> io::Result<usize> {
        unsafe {
            let mut bytes = 0;
            let wait = if wait { c::TRUE } else { c::FALSE };
            let res = cvt(c::GetOverlappedResult(
                self.as_raw_handle(),
                overlapped,
                &mut bytes,
                wait,
            ));
            match res {
                Ok(_) => Ok(bytes as usize),
                Err(e) => {
                    if e.raw_os_error() == Some(c::ERROR_HANDLE_EOF as i32)
                        || e.raw_os_error() == Some(c::ERROR_BROKEN_PIPE as i32)
                    {
                        Ok(0)
                    } else {
                        Err(e)
                    }
                }
            }
        }
    }

    pub fn cancel_io(&self) -> io::Result<()> {
        unsafe { cvt(c::CancelIo(self.as_raw_handle() as isize)).map(drop) }
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.synchronous_write(&buf, None)
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        default_write_vectored(|buf| self.write(buf), bufs)
    }

    #[inline]
    pub fn is_write_vectored(&self) -> bool {
        false
    }

    pub fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize> {
        self.synchronous_write(&buf, Some(offset))
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self(self.0.try_clone()?))
    }

    pub fn duplicate(
        &self,
        access: c::DWORD,
        inherit: bool,
        options: c::DWORD,
    ) -> io::Result<Self> {
        let new_handle = duplicate_handle(self.as_raw_handle(), access, inherit, options)?;
        Ok(Self(new_handle))
    }

    /// Performs a synchronous read.
    ///
    /// If the handle is opened for asynchronous I/O then this abort the process.
    /// See #81357.
    ///
    /// If `offset` is `None` then the current file position is used.
    unsafe fn synchronous_read(
        &self,
        buf: *mut mem::MaybeUninit<u8>,
        len: usize,
        offset: Option<u64>,
    ) -> io::Result<usize> {
        let mut io_status = c::IO_STATUS_BLOCK::PENDING;

        // The length is clamped at u32::MAX.
        let len = cmp::min(len, c::DWORD::MAX as usize) as c::DWORD;
        let status = c::NtReadFile(
            self.as_handle(),
            ptr::null_mut(),
            None,
            ptr::null_mut(),
            &mut io_status,
            buf,
            len,
            offset.map(|n| n as _).as_ref(),
            None,
        );

        let status = if status == c::STATUS_PENDING {
            c::WaitForSingleObject(self.as_raw_handle() as isize, c::INFINITE);
            io_status.status()
        } else {
            status
        };
        match status {
            // If the operation has not completed then abort the process.
            // Doing otherwise means that the buffer and stack may be written to
            // after this function returns.
            c::STATUS_PENDING => panic!("I/O error: operation failed to complete synchronously"),

            // Return `Ok(0)` when there's nothing more to read.
            c::STATUS_END_OF_FILE => Ok(0),

            // Success!
            status if c::nt_success(status) => Ok(io_status.Information),

            status => {
                let error = c::RtlNtStatusToDosError(status);
                Err(io::Error::from_raw_os_error(error as _))
            }
        }
    }
    /// Performs a synchronous write.
    ///
    /// If the handle is opened for asynchronous I/O then this abort the process.
    /// See #81357.
    ///
    /// If `offset` is `None` then the current file position is used.
    fn synchronous_write(&self, buf: &[u8], offset: Option<u64>) -> io::Result<usize> {
        let mut io_status = c::IO_STATUS_BLOCK::PENDING;

        // The length is clamped at u32::MAX.
        let len = cmp::min(buf.len(), c::DWORD::MAX as usize) as c::DWORD;
        let status = unsafe {
            c::NtWriteFile(
                self.as_handle(),
                ptr::null_mut(),
                None,
                ptr::null_mut(),
                &mut io_status,
                buf.as_ptr(),
                len,
                offset.map(|n| n as _).as_ref(),
                None,
            )
        };
        let status = if status == c::STATUS_PENDING {
            unsafe { c::WaitForSingleObject(self.as_raw_handle() as isize, c::INFINITE) };
            io_status.status()
        } else {
            status
        };
        match status {
            // If the operation has not completed then abort the process.
            // Doing otherwise means that the buffer may be read and the stack
            // written to after this function returns.
            c::STATUS_PENDING => panic!("I/O error: operation failed to complete synchronously"),

            // Success!
            status if c::nt_success(status) => Ok(io_status.Information),

            status => {
                let error = unsafe { c::RtlNtStatusToDosError(status) };
                Err(io::Error::from_raw_os_error(error as _))
            }
        }
    }
}

fn duplicate_handle(
    raw_handle: c::HANDLE,
    access: u32,
    inherit: bool,
    options: u32,
) -> io::Result<OwnedHandle> {
    // `Stdin`, `Stdout`, and `Stderr` can all hold null handles, such as
    // in a process with a detached console. `DuplicateHandle` would fail
    // if we passed it a null handle, but we can treat null as a valid
    // handle which doesn't do any I/O, and allow it to be duplicated.
    if raw_handle.is_null() {
        return unsafe { Ok(OwnedHandle::from_raw_handle(raw_handle)) };
    }

    let mut ret = ptr::null_mut();
    cvt(unsafe {
        let cur_proc = c::GetCurrentProcess();
        c::DuplicateHandle(
            cur_proc,
            raw_handle,
            cur_proc,
            &mut ret,
            access,
            inherit as c::BOOL,
            options,
        )
    })?;
    unsafe { Ok(OwnedHandle::from_raw_handle(ret)) }
}

impl<'a> Read for &'a Handle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read(buf)
    }

    fn read_buf(&mut self, buf: BorrowedCursor<'_>) -> io::Result<()> {
        (**self).read_buf(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        (**self).read_vectored(bufs)
    }

    #[inline]
    fn is_read_vectored(&self) -> bool {
        (**self).is_read_vectored()
    }
}
