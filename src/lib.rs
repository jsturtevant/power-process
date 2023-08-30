#![feature(os_str_bytes)]
#![feature(maybe_uninit_slice)]
#![feature(maybe_uninit_uninit_array)]
#![feature(raw_os_nonzero)]
#![feature(strict_provenance)]
#![feature(read_buf)]
#![feature(can_vector)]

pub mod super_command;
mod command;
mod args;
mod process;
mod env;
mod c;
mod path_ext;
mod windows;
mod wstr;
mod pipe;
mod handle;
mod file;

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    #[test]
    fn it_works() {
        // standard
        let out = Command::new("cmd")
        .args(["/C", "echo hello"])
        .output().unwrap();
        println!("code {:?}", out.status.code());
        assert!(out.status.success());
        assert_eq!(out.stdout, b"hello\r\n");

        // super
        let out = super_command::Command::new("cmd")
                .args(["/C", "echo hello"])
                .output().unwrap();
        println!("code {:?}", out.status.code());
        assert!(out.status.success());
        assert_eq!(out.stderr, b"hello\r\n");
    }
}
