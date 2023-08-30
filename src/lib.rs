#![feature(os_str_bytes)]
#![feature(maybe_uninit_slice)]
#![feature(maybe_uninit_uninit_array)]
#![feature(raw_os_nonzero)]
#![feature(strict_provenance)]
#![feature(read_buf)]
#![feature(can_vector)]

mod args;
mod c;
mod command;
mod env;
mod file;
mod handle;
mod path_ext;
mod pipe;
mod process;
pub mod super_command;
mod windows;
mod wstr;

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

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

        // super
        let mut out = super_command::Command::new("cmd")
            .args(["/C", "echo", "hello test"])
            .spawn()
            .expect("success");
        let code = out.wait().expect("success");
        println!("code {:?}", code);

        // super output
        let out2 = super_command::Command::new("cmd")
            .args(["/C", "echo", "hello"])
            .output()
            .unwrap();
        println!("code {:?}", out2.status.code());
        assert_eq!(out2.stdout, b"hello\r\n");
        assert!(out2.status.success());
    }
}
