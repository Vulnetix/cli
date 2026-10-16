use axum::extract::Query;

pub async fn exec(script: String) {
~>    let child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&script)
        .spawn();
    let _ = child;
}

pub async fn run_tool(Query(params): Query<Tool>) -> String {
~>    let out = std::process::Command::new(&params.name).output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}
