use std::{
    ffi::OsStr,
    io::{self, ErrorKind},
    mem::{MaybeUninit, self},
    os::windows::prelude::OsStrExt,
};

use crate::c;

// Many Windows APIs follow a pattern of where we hand a buffer and then they
// will report back to us how large the buffer should be or how many bytes
// currently reside in the buffer. This function is an abstraction over these
// functions by making them easier to call.
//
// The first callback, `f1`, is yielded a (pointer, len) pair which can be
// passed to a syscall. The `ptr` is valid for `len` items (u16 in this case).
// The closure is expected to return what the syscall returns which will be
// interpreted by this function to determine if the syscall needs to be invoked
// again (with more buffer space).
//
// Once the syscall has completed (errors bail out early) the second closure is
// yielded the data which has been read from the syscall. The return value
// from this closure is then the return value of the function.
pub fn fill_utf16_buf<F1, F2, T>(mut f1: F1, f2: F2) -> io::Result<T>
where
    F1: FnMut(*mut u16, c::DWORD) -> c::DWORD,
    F2: FnOnce(&[u16]) -> T,
{
    // Start off with a stack buf but then spill over to the heap if we end up
    // needing more space.
    //
    // This initial size also works around `GetFullPathNameW` returning
    // incorrect size hints for some short paths:
    // https://github.com/dylni/normpath/issues/5
    //
    // note inlined #[unstable(feature = "maybe_uninit_uninit_array", issue = "96097")]
    let mut stack_buf: [MaybeUninit<u16>; 512] = unsafe { MaybeUninit::<[MaybeUninit<u16>; 512]>::uninit().assume_init() };
    let mut heap_buf: Vec<MaybeUninit<u16>> = Vec::new();
    unsafe {
        let mut n = stack_buf.len();
        loop {
            let buf = if n <= stack_buf.len() {
                &mut stack_buf[..]
            } else {
                let extra = n - heap_buf.len();
                heap_buf.reserve(extra);
                // We used `reserve` and not `reserve_exact`, so in theory we
                // may have gotten more than requested. If so, we'd like to use
                // it... so long as we won't cause overflow.
                n = heap_buf.capacity().min(c::DWORD::MAX as usize);
                // Safety: MaybeUninit<u16> does not need initialization
                heap_buf.set_len(n);
                &mut heap_buf[..]
            };

            // This function is typically called on windows API functions which
            // will return the correct length of the string, but these functions
            // also return the `0` on error. In some cases, however, the
            // returned "correct length" may actually be 0!
            //
            // To handle this case we call `SetLastError` to reset it to 0 and
            // then check it again if we get the "0 error value". If the "last
            // error" is still 0 then we interpret it as a 0 length buffer and
            // not an actual error.
            c::SetLastError(0);
            let k = match f1(buf.as_mut_ptr().cast::<u16>(), n as c::DWORD) {
                0 if c::GetLastError() == 0 => 0,
                0 => return Err(io::Error::last_os_error()),
                n => n,
            } as usize;
            if k == n && c::GetLastError() == c::ERROR_INSUFFICIENT_BUFFER {
                n = n.saturating_mul(2).min(c::DWORD::MAX as usize);
            } else if k > n {
                n = k;
            } else if k == n {
                // It is impossible to reach this point.
                // On success, k is the returned string length excluding the null.
                // On failure, k is the required buffer length including the null.
                // Therefore k never equals n.
                unreachable!();
            } else {
                // Safety: First `k` values are initialized.
                let slice: &[u16] = slice_assume_init_ref(&buf[..k]);
                return Ok(f2(slice));
            }
        }
    }
}

// inlined
//#[unstable(feature = "maybe_uninit_slice", issue = "63569")]
// #[rustc_const_unstable(feature = "maybe_uninit_slice", issue = "63569")]
pub const unsafe fn slice_assume_init_ref(slice: &[MaybeUninit<u16>]) -> &[u16] {
    // SAFETY: casting `slice` to a `*const [T]` is safe since the caller guarantees that
    // `slice` is initialized, and `MaybeUninit` is guaranteed to have the same layout as `T`.
    // The pointer obtained is valid since it refers to memory owned by `slice` which is a
    // reference and thus guaranteed to be valid for reads.
    unsafe { &*(slice as *const [_] as *const [u16]) }
}

pub(crate) fn ensure_no_nuls<T: AsRef<OsStr>>(str: T) -> io::Result<T> {
    if str.as_ref().encode_wide().any(|b| b == 0) {
        Err(io::Error::new(
            ErrorKind::InvalidInput,
            "nul byte found in provided data",
        ))
    } else {
        Ok(str)
    }
}

pub(crate) fn to_u16s<S: AsRef<OsStr>>(s: S) -> io::Result<Vec<u16>> {
    fn inner(s: &OsStr) -> io::Result<Vec<u16>> {
        // Most paths are ASCII, so reserve capacity for as much as there are bytes
        // in the OsStr plus one for the null-terminating character. We are not
        // wasting bytes here as paths created by this function are primarily used
        // in an ephemeral fashion.
        let mut maybe_result = Vec::with_capacity(s.len() + 1);
        maybe_result.extend(s.encode_wide());

        if unrolled_find_u16s(0, &maybe_result).is_some() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "strings passed to WinAPI cannot contain NULs",
            ));
        }
        maybe_result.push(0);
        Ok(maybe_result)
    }
    inner(s.as_ref())
}

pub fn unrolled_find_u16s(needle: u16, haystack: &[u16]) -> Option<usize> {
    let ptr = haystack.as_ptr();
    let mut start = haystack;

    // For performance reasons unfold the loop eight times.
    while start.len() >= 8 {
        macro_rules! if_return {
            ($($n:literal,)+) => {
                $(
                    if start[$n] == needle {
                        return Some((addr((&start[$n] as *const u16)) - addr(ptr)) / 2);
                    }
                )+
            }
        }

        if_return!(0, 1, 2, 3, 4, 5, 6, 7,);

        start = &start[8..];
    }

    for c in start {
        if *c == needle {
            return Some((addr(c as *const u16) - addr(ptr)) / 2);
        }
    }
    None
}

// inlined for #![feature(strict_provenance)]
pub fn addr<T: ?Sized>(t: *const T ) -> usize {
    // FIXME(strict_provenance_magic): I am magic and should be a compiler intrinsic.
    // SAFETY: Pointer-to-integer transmutes are valid (if you are okay with losing the
    // provenance).
    unsafe { mem::transmute(t.cast::<()>()) }
}

pub fn hashmap_random_keys() -> (u64, u64) {
    let mut v = (0, 0);
    let ret = unsafe {
        c::BCryptGenRandom(
            0_isize,
            &mut v as *mut _ as *mut u8,
            std::mem::size_of_val(&v) as c::ULONG,
            c::BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if c::nt_success(ret) {
        v
    } else {
        fallback_rng()
    }
}

/// Generate random numbers using the fallback RNG function (RtlGenRandom)
///
/// This is necessary because of a failure to load the SysWOW64 variant of the
/// bcryptprimitives.dll library from code that lives in bcrypt.dll
/// See <https://bugzilla.mozilla.org/show_bug.cgi?id=1788004#c9>
#[cfg(not(target_vendor = "uwp"))]
#[inline(never)]
fn fallback_rng() -> (u64, u64) {
    use std::ffi::c_void;

    let mut v = (0, 0);
    let ret = unsafe {
        c::RtlGenRandom(
            &mut v as *mut _ as *mut c_void,
            std::mem::size_of_val(&v) as c::ULONG,
        )
    };

    if ret != 0 {
        v
    } else {
        panic!("fallback RNG broken: {}", io::Error::last_os_error())
    }
}

/// We can't use RtlGenRandom with UWP, so there is no fallback
#[cfg(target_vendor = "uwp")]
#[inline(never)]
fn fallback_rng() -> (u64, u64) {
    panic!("fallback RNG broken: RtlGenRandom() not supported on UWP");
}
