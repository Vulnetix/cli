use axum::extract::Query;
use std::process::Command;

#[derive(serde::Deserialize)]
pub struct Conv {
    file: String,
}

pub async fn convert(Query(q): Query<Conv>) -> String {
    let out = Command::new("convert")
        .arg("--")
        .arg(&q.file)
        .arg("out.png")
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}
