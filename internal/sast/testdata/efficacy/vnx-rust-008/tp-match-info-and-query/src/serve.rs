use actix_web::{web, HttpRequest, HttpResponse};
use std::path::PathBuf;

async fn show(req: HttpRequest) -> HttpResponse {
    let name: PathBuf = req.match_info().query("filename").parse().unwrap();
~>    let p = PathBuf::from("uploads").join(name);
    match std::fs::read(&p) {
        Ok(b) => HttpResponse::Ok().body(b),
        Err(_) => HttpResponse::NotFound().finish(),
    }
}

#[derive(serde::Deserialize)]
struct FileParams {
    file: String,
}

async fn export(params: web::Query<FileParams>) -> HttpResponse {
~>    let body = std::fs::read_to_string(format!("/var/data/{}", params.file)).unwrap_or_default();
    HttpResponse::Ok().body(body)
}
