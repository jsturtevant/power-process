#[cfg(test)]
mod upstream {

    #[test]
    #[cfg(windows)]
    fn test_proc_thread_attributes() {
        use std::mem;
        use std::os::windows::io::AsRawHandle;
        use crate::power_command::{CommandExt, Command, Child};
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

        struct ProcessDropGuard(Child);

        impl Drop for ProcessDropGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
            }
        }

        let parent = ProcessDropGuard(Command::new("cmd").spawn().unwrap());

        let mut child_cmd = Command::new("cmd");

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