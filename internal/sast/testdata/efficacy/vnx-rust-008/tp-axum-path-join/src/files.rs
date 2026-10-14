use axum::{extract::Path, http::StatusCode};

pub async fn download(Path(name): Path<String>) -> Result<Vec<u8>, StatusCode> {
    let base = std::path::Path::new("/srv/files");
~>    let full = base.join(&name);
    tokio::fs::read(full).await.map_err(|_| StatusCode::NOT_FOUND)
}

pub async fn raw(
    Path(file): Path<String>,
) -> Result<String, StatusCode> {
~>    std::fs::read_to_string(std::path::Path::new("/srv/raw").join(file))
        .map_err(|_| StatusCode::NOT_FOUND)
}
