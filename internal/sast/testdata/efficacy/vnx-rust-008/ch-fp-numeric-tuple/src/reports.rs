use axum::extract::Path;
use std::path::PathBuf;

pub async fn report(Path((year, month)): Path<(u16, u8)>) -> Vec<u8> {
    let file = PathBuf::from("/srv/reports").join(format!("{}-{:02}.pdf", year, month));
    std::fs::read(file).unwrap_or_default()
}
