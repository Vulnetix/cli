use std::process::Command;

pub fn grep(term: &str) {
    let safe = shlex::try_quote(term).unwrap();
    let cmd = format!("grep -r {} .", safe);
    Command::new("sh").arg("-c").arg(cmd).status().unwrap();
}

// Command::new("sh").arg("-c").arg(format!("rm {}", x))
pub fn s() -> &'static str {
    "Command::new(\"sh\").arg(\"-c\").arg(format!(\"{}\", x))"
}
