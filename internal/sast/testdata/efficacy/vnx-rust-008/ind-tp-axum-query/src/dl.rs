use axum::extract::Query;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Params { file: String }

pub async fn download(Query(q): Query<Params>) -> Vec<u8> {
~>    std::fs::read(format!("/srv/exports/{}", q.file)).unwrap()
}
