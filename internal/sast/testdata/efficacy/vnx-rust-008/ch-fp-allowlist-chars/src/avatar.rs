use axum::extract::Path;
use axum::http::StatusCode;
use std::path::PathBuf;

pub async fn avatar(Path(user): Path<String>) -> Result<Vec<u8>, StatusCode> {
    if !user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(StatusCode::BAD_REQUEST);
    }
    let file = PathBuf::from("/srv/avatars").join(format!("{}.png", user));
    std::fs::read(file).map_err(|_| StatusCode::NOT_FOUND)
}
