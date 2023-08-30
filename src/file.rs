use std::{
    fs::File,
    io,
    os::windows::prelude::{HandleOrInvalid, OwnedHandle, RawHandle},
    path::Path,
    ptr,
};

use crate::{c, path_ext};

pub fn open(path: &Path, opts: &OpenOptions) -> io::Result<File> {
    let path = path_ext::maybe_verbatim(path)?;
    let handle = unsafe {
        c::CreateFileW(
            path.as_ptr(),
            opts.get_access_mode()?,
            opts.share_mode,
            opts.security_attributes,
            opts.get_creation_mode()?,
            opts.get_flags_and_attributes(),
            0,
        )
    };
    let handle = unsafe { HandleOrInvalid::from_raw_handle(handle as RawHandle) };
    if let Ok(handle) = OwnedHandle::try_from(handle) {
        Ok(File::from(handle))
    } else {
        Err(io::Error::last_os_error())
    }
}

pub struct OpenOptions {
    // generic
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    // system-specific
    custom_flags: u32,
    access_mode: Option<c::DWORD>,
    attributes: c::DWORD,
    share_mode: c::DWORD,
    security_qos_flags: c::DWORD,
    security_attributes: c::LPSECURITY_ATTRIBUTES,
}
impl OpenOptions {
    pub fn new() -> OpenOptions {
        OpenOptions {
            // generic
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
            // system-specific
            custom_flags: 0,
            access_mode: None,
            share_mode: c::FILE_SHARE_READ | c::FILE_SHARE_WRITE | c::FILE_SHARE_DELETE,
            attributes: 0,
            security_qos_flags: 0,
            security_attributes: ptr::null_mut(),
        }
    }

    pub fn read(&mut self, read: bool) {
        self.read = read;
    }
    pub fn write(&mut self, write: bool) {
        self.write = write;
    }
    pub fn append(&mut self, append: bool) {
        self.append = append;
    }
    pub fn truncate(&mut self, truncate: bool) {
        self.truncate = truncate;
    }
    pub fn create(&mut self, create: bool) {
        self.create = create;
    }
    pub fn create_new(&mut self, create_new: bool) {
        self.create_new = create_new;
    }

    pub fn custom_flags(&mut self, flags: u32) {
        self.custom_flags = flags;
    }
    pub fn access_mode(&mut self, access_mode: u32) {
        self.access_mode = Some(access_mode);
    }
    pub fn share_mode(&mut self, share_mode: u32) {
        self.share_mode = share_mode;
    }
    pub fn attributes(&mut self, attrs: u32) {
        self.attributes = attrs;
    }
    pub fn security_qos_flags(&mut self, flags: u32) {
        // We have to set `SECURITY_SQOS_PRESENT` here, because one of the valid flags we can
        // receive is `SECURITY_ANONYMOUS = 0x0`, which we can't check for later on.
        self.security_qos_flags = flags | c::SECURITY_SQOS_PRESENT;
    }
    pub fn security_attributes(&mut self, attrs: c::LPSECURITY_ATTRIBUTES) {
        self.security_attributes = attrs;
    }

    fn get_access_mode(&self) -> io::Result<c::DWORD> {
        const ERROR_INVALID_PARAMETER: i32 = 87;

        match (self.read, self.write, self.append, self.access_mode) {
            (.., Some(mode)) => Ok(mode),
            (true, false, false, None) => Ok(c::GENERIC_READ),
            (false, true, false, None) => Ok(c::GENERIC_WRITE),
            (true, true, false, None) => Ok(c::GENERIC_READ | c::GENERIC_WRITE),
            (false, _, true, None) => Ok(c::FILE_GENERIC_WRITE & !c::FILE_WRITE_DATA),
            (true, _, true, None) => {
                Ok(c::GENERIC_READ | (c::FILE_GENERIC_WRITE & !c::FILE_WRITE_DATA))
            }
            (false, false, false, None) => {
                Err(io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER))
            }
        }
    }

    fn get_creation_mode(&self) -> io::Result<c::DWORD> {
        const ERROR_INVALID_PARAMETER: i32 = 87;

        match (self.write, self.append) {
            (true, false) => {}
            (false, false) => {
                if self.truncate || self.create || self.create_new {
                    return Err(io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER));
                }
            }
            (_, true) => {
                if self.truncate && !self.create_new {
                    return Err(std::io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER));
                }
            }
        }

        Ok(match (self.create, self.truncate, self.create_new) {
            (false, false, false) => c::OPEN_EXISTING,
            (true, false, false) => c::OPEN_ALWAYS,
            (false, true, false) => c::TRUNCATE_EXISTING,
            (true, true, false) => c::CREATE_ALWAYS,
            (_, _, true) => c::CREATE_NEW,
        })
    }

    fn get_flags_and_attributes(&self) -> c::DWORD {
        self.custom_flags
            | self.attributes
            | self.security_qos_flags
            | if self.create_new {
                c::FILE_FLAG_OPEN_REPARSE_POINT
            } else {
                0
            }
    }
}
