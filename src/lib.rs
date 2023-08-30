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
    use std::process::Command;

    use super::*;

    #[test]
    fn it_works() {
        // standard
        let out = Command::new("cmd")
            .args(["/C", "echo hello"])
            .output()
            .unwrap();
        println!("code {:?}", out.status.code());
        assert!(out.status.success());
        assert_eq!(out.stdout, b"hello\r\n");

        // super
        let out = super_command::Command::new("cmd")
            .args(["/C", "echo hello"])
            .output()
            .unwrap();
        println!("code {:?}", out.status.code());
        assert!(out.status.success());
        assert_eq!(out.stderr, b"hello\r\n");
    }
}
