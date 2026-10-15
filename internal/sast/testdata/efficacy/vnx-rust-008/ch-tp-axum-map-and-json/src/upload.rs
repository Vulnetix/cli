use axum::extract::{Json, Path};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(serde::Deserialize)]
pub struct Upload {
    filename: String,
    data: Vec<u8>,
}

pub async fn get_file(Path(params): Path<HashMap<String, String>>) -> Vec<u8> {
    let root = PathBuf::from("/srv/files");
    let file = params.get("file").cloned().unwrap_or_default();
~>    std::fs::read(root.join(&file)).unwrap_or_default()
}

pub async fn put_file(Json(body): Json<Upload>) -> &'static str {
    let dir = PathBuf::from("/srv/uploads");
~>    tokio::fs::write(dir.join(&body.filename), &body.data).await.ok();
    "ok"
}
