mod args;
mod c;
mod child;
mod command;
mod env;
mod file;
mod handle;
mod path_ext;
mod pipe;
pub mod power_command;
mod util;

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::prelude::AsRawHandle;
    use std::process::Command;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::{CreateJobObjectW, IsProcessInJob};
    use windows::core::w;
    use windows_sys::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_JOB_LIST;
    use windows_sys::Win32::Foundation::{BOOL};
    use crate::power_command::CommandExt;


    #[test]
    fn it_works() {
        // standard
        let out = Command::new("cmd")
            .args(["/C", "echo", "hello"])
            .output()
            .unwrap();
        println!("code {:?}", out.status.code());
        assert!(out.status.success());
        assert_eq!(out.stdout, b"hello\r\n");

        // super status
        let mut out = power_command::Command::new("cmd")
            .args(["/C", "echo", "hello test"])
            .spawn()
            .expect("success");
        let code = out.wait().expect("success");
        println!("code {:?}", code);

        // super output
        let out2 = power_command::Command::new("cmd")
            .args(["/C", "echo", "hello"])
            .output()
            .unwrap();
        println!("code {:?}", out2.status.code());
        assert_eq!(out2.stdout, b"hello\r\n");
        assert!(out2.status.success());

        //super status
        let mut out = power_command::Command::new("cmd")
            .args(["/C", "echo", "hello test"])
            .spawn()
            .expect("success");
        let code = out.wait().expect("success");
        println!("code {:?}", code);
    }

    #[test]
    // https://devblogs.microsoft.com/oldnewthing/20230209-00/?p=107812
    fn creates_process_in_job() {
        let job_handle = unsafe { CreateJobObjectW(None, w!("power-process-job")) }.unwrap();
        let mut cmd = power_command::Command::new("cmd");

        //cmd.args(["/C", "echo", "hello"]);
        unsafe { cmd.raw_attribute(PROC_THREAD_ATTRIBUTE_JOB_LIST as usize, job_handle);}


        let child = cmd.spawn().unwrap();

        let child_handle = child.handle().as_raw_handle() as isize;
        let mut  result = 0 as BOOL;
        let result_ptr: *mut BOOL = &mut result;
        unsafe { IsProcessInJob(HANDLE(child_handle), job_handle, result_ptr as *mut _) }.unwrap();

        assert_eq!(result, 1);
    }

    #[test]
    #[cfg(windows)]
    fn test_proc_thread_attributes() {
        use std::mem;
        use std::os::windows::io::AsRawHandle;
        use crate::power_command::CommandExt;
        use crate::c::{CloseHandle, BOOL, HANDLE};
        use cvt::cvt;
        use windows_sys::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_PARENT_PROCESS;

        #[repr(C)]
        #[allow(non_snake_case)]
        struct PROCESSENTRY32W {
            dwSize: u32,
            cntUsage: u32,
            th32ProcessID: u32,
            th32DefaultHeapID: usize,
            th32ModuleID: u32,
            cntThreads: u32,
            th32ParentProcessID: u32,
            pcPriClassBase: i32,
            dwFlags: u32,
            szExeFile: [u16; 260],
        }

        extern "system" {
            fn CreateToolhelp32Snapshot(dwflags: u32, th32processid: u32) -> HANDLE;
            fn Process32First(hsnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
            fn Process32Next(hsnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
        }

        //const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020000;
        const TH32CS_SNAPPROCESS: u32 = 0x00000002;

        struct ProcessDropGuard(crate::child::Child);

        impl Drop for ProcessDropGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
            }
        }

        let parent = ProcessDropGuard(power_command::Command::new("cmd").spawn().unwrap());

        let mut child_cmd = power_command::Command::new("cmd");

        unsafe {
            child_cmd
                .raw_attribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize, parent.0.as_raw_handle() as isize);
        }

        let child = ProcessDropGuard(child_cmd.spawn().unwrap());

        let h_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

        let mut process_entry = PROCESSENTRY32W {
            dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
            cntUsage: 0,
            th32ProcessID: 0,
            th32DefaultHeapID: 0,
            th32ModuleID: 0,
            cntThreads: 0,
            th32ParentProcessID: 0,
            pcPriClassBase: 0,
            dwFlags: 0,
            szExeFile: [0; 260],
        };

        unsafe { cvt(Process32First(h_snapshot, &mut process_entry as *mut _)) }.unwrap();

        loop {
            if child.0.id() == process_entry.th32ProcessID {
                break;
            }
            unsafe { cvt(Process32Next(h_snapshot, &mut process_entry as *mut _)) }.unwrap();
        }

        unsafe { cvt(CloseHandle(h_snapshot)) }.unwrap();

        assert_eq!(parent.0.id(), process_entry.th32ParentProcessID);

        drop(child)
    }


}
