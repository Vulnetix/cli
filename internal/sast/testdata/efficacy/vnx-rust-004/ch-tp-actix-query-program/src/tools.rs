use actix_web::{get, web, HttpResponse};
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize)]
struct ToolReq {
    tool: String,
    target: String,
}

#[get("/diag")]
async fn diag(req: web::Query<ToolReq>) -> HttpResponse {
~>    let out = Command::new(&req.tool).arg(&req.target).output().unwrap();
    HttpResponse::Ok().body(out.stdout)
}
