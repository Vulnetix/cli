use tokio::process::Command;

pub async fn run_hook(repo: &str, hook: &str) -> anyhow::Result<()> {
    let line = format!("cd {} && ./hooks/{}", repo, hook);
~>    let status = Command::new("sh")
        .arg("-c")
        .arg(
            line,
        )
        .status()
        .await?;
    anyhow::ensure!(status.success());
    Ok(())
}
