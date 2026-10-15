use actix_web::{get, web, HttpResponse};

#[get("/logs/{service}")]
async fn logs(service: web::Path<String>) -> HttpResponse {
    let service = service.into_inner();
~>    match std::fs::read_to_string(format!("/var/log/app/{service}.log")) {
        Ok(body) => HttpResponse::Ok().body(body),
        Err(_) => HttpResponse::NotFound().finish(),
    }
}
