use actix_files::NamedFile;
use actix_web::{get, web};
use std::path::{Component, Path};

#[get("/static/{filename}")]
async fn asset(path: web::Path<String>) -> actix_web::Result<NamedFile> {
    let filename = path.into_inner();
    if filename.contains("..") || filename.contains('/') {
        return Err(actix_web::error::ErrorBadRequest("bad name"));
    }
    Ok(NamedFile::open(format!("./static/{}", filename))?)
}

#[get("/img/{name}")]
async fn image(name: web::Path<String>) -> actix_web::Result<NamedFile> {
    let leaf = Path::new(name.as_str()).file_name().ok_or_else(|| actix_web::error::ErrorBadRequest("x"))?;
    Ok(NamedFile::open(Path::new("./img").join(leaf))?)
}

#[get("/raw/{p}")]
async fn raw(p: web::Path<String>) -> actix_web::Result<NamedFile> {
    let rel = Path::new(p.as_str());
    if !rel.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(actix_web::error::ErrorBadRequest("x"));
    }
    Ok(NamedFile::open(Path::new("./raw").join(rel))?)
}
