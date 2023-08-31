use std::os::windows::prelude::AsRawHandle;

use power_process::power_command::{Command, CommandExt};
use windows::{Win32::{System::JobObjects::{CreateJobObjectW, IsProcessInJob}, Foundation::{HANDLE}}, core::w};
use windows_sys::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_JOB_LIST;
use windows_sys::Win32::Foundation::BOOL;

fn main(){
    let job_handle = unsafe { CreateJobObjectW(None, w!("power-process-job")) }.unwrap();
    let mut cmd = Command::new("cmd");
    cmd.args(["/C", "echo", "hello from job"]);
    unsafe { cmd.raw_attribute(PROC_THREAD_ATTRIBUTE_JOB_LIST as usize, job_handle);}


    let child = cmd.spawn().unwrap();

    let child_handle = child.as_raw_handle() as isize;
    let mut  result = 0 as BOOL;
    let result_ptr: *mut BOOL = &mut result;
    unsafe { IsProcessInJob(HANDLE(child_handle), job_handle, result_ptr as *mut _) }.unwrap();

    assert_eq!(result, 1);
}