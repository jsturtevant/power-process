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
mod windows;

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
    }
}
