use actix_web::{web, HttpResponse, Responder};
use std::path::PathBuf;

async fn serve_file(filename: web::Path<String>) -> impl Responder {
    let base = PathBuf::from("/var/www/files");
~>    let path = base.join(filename.as_str());
    match tokio::fs::read(&path).await {
        Ok(data) => HttpResponse::Ok().body(data),
        Err(_) => HttpResponse::NotFound().finish(),
    }
}
