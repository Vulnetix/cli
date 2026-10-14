// Never do: Command::new("sh").arg("-c").arg(format!("rm {}", path))
pub const BAD: &str = "Command::new(\"sh\").arg(\"-c\").arg(user)";

/// Use `Command::new("ls").arg(dir)` instead of a shell.
pub fn noop() {}
