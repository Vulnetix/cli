use axum::extract::Path;
use std::path::PathBuf;

pub async fn download(Path(name): Path<String>) -> Result<Vec<u8>, u16> {
    let base = PathBuf::from("/srv/data").canonicalize().map_err(|_| 500u16)?;
    let full = base.join(&name).canonicalize().map_err(|_| 404u16)?;
    if !full.starts_with(&base) {
        return Err(403);
    }
    Ok(tokio::fs::read(full).await.map_err(|_| 404u16)?)
}
