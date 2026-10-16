use actix_web::web;
use std::path::Path;

pub async fn a(name: web::Path<String>) -> Vec<u8> {
    let safe = Path::new(name.as_str()).file_name().unwrap();
    std::fs::read(Path::new("/srv/pub").join(safe)).unwrap()
}

pub async fn b(name: web::Path<String>) -> Option<Vec<u8>> {
    if name.contains("..") {
        return None;
    }
    std::fs::read(format!("/srv/pub/{}", name)).ok()
}
