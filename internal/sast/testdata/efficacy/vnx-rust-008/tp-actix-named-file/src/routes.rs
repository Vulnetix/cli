use actix_files::NamedFile;
use actix_web::{get, web};

#[get("/static/{filename}")]
async fn asset(path: web::Path<String>) -> actix_web::Result<NamedFile> {
    let filename = path.into_inner();
~>    Ok(NamedFile::open(format!("./static/{}", filename))?)
}

#[get("/docs/{doc}")]
async fn doc(info: web::Path<String>) -> actix_web::Result<NamedFile> {
    let p = format!("./docs/{}.html", info);
~>    Ok(NamedFile::open(p)?)
}
