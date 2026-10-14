use axum::extract::{Path, Query};
use std::collections::HashMap;

pub async fn user_file(Path((user, file)): Path<(String, String)>) -> Vec<u8> {
~>    let target = std::path::PathBuf::from("/home/data").join(&user).join(&file);
    std::fs::read(target).unwrap_or_default()
}

pub async fn remove(Query(q): Query<HashMap<String, String>>) {
    let victim = q.get("path").cloned().unwrap_or_default();
~>    let _ = tokio::fs::remove_file(format!("/tmp/uploads/{}", victim)).await;
}
