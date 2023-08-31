mod args;
mod c;
mod process;
mod command;
mod env;
mod file;
mod handle;
mod path_ext;
mod pipe;
pub mod power_command;
mod util;
mod upstream_tests;
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

        let child_handle = child.as_raw_handle() as isize;
        let mut  result = 0 as BOOL;
        let result_ptr: *mut BOOL = &mut result;
        unsafe { IsProcessInJob(HANDLE(child_handle), job_handle, result_ptr as *mut _) }.unwrap();

        assert_eq!(result, 1);
    }

 
}
