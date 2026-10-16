use actix_web::{HttpRequest, Result};
use actix_files::NamedFile;

pub async fn get(req: HttpRequest) -> Result<NamedFile> {
    let name = req.match_info().get("name").unwrap();
~>    Ok(NamedFile::open(format!("static/{}", name))?)
}

pub async fn tup(axum::extract::Path((dir, file)): axum::extract::Path<(String, String)>) -> Vec<u8> {
~>    tokio::fs::read(std::path::Path::new("/data").join(&dir).join(&file)).await.unwrap()
}
