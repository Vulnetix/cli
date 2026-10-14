use axum::{extract::Path, http::StatusCode};

pub async fn download(Path(name): Path<String>) -> Result<Vec<u8>, StatusCode> {
    let base = std::fs::canonicalize("/srv/files").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let full = base
        .join(&name)
        .canonicalize()
        .map_err(|_| StatusCode::NOT_FOUND)?;
    if !full.starts_with(&base) {
        return Err(StatusCode::FORBIDDEN);
    }
    tokio::fs::read(full).await.map_err(|_| StatusCode::NOT_FOUND)
}
