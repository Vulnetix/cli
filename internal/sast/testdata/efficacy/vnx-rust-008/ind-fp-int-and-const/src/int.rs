use axum::extract::Path;

pub async fn by_id(Path(id): Path<u64>) -> Vec<u8> {
    std::fs::read(format!("/srv/blobs/{}.bin", id)).unwrap()
}

pub async fn fixed() -> Vec<u8> {
    std::fs::read("/srv/blobs/index.html").unwrap()
}

pub async fn uid(Path(id): Path<uuid::Uuid>) -> Vec<u8> {
    std::fs::read(std::path::Path::new("/srv/u").join(id.to_string())).unwrap()
}
