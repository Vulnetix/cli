use actix_files::NamedFile;
use actix_web::HttpRequest;
use std::path::PathBuf;

async fn index(req: HttpRequest) -> actix_web::Result<NamedFile> {
    let path: PathBuf = req.match_info().query("filename").parse().unwrap();
~>    Ok(NamedFile::open(path)?)
}
