use axum::extract::Query;
use std::process::Command;

#[derive(serde::Deserialize)]
pub struct Tool {
    name: String,
}

pub async fn run_tool(Query(params): Query<Tool>) -> String {
~>    let out = Command::new(&params.name).output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub async fn run_actix(form: actix_web::web::Form<Tool>) -> String {
    let program = form.name.clone();
~>    let out = Command::new(program).output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}
