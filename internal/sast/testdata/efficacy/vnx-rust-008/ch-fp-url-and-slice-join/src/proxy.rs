use axum::extract::{Path, Query};
use url::Url;

#[derive(serde::Deserialize)]
pub struct Tags {
    tags: Vec<String>,
}

pub async fn upstream(Path(name): Path<String>) -> String {
    let base = Url::parse("https://registry.example.invalid/v2/").unwrap();
    let target = base.join(&name).unwrap();
    target.to_string()
}

pub async fn label(Query(t): Query<Tags>) -> String {
    let joined = t.tags.join(",");
    joined
}
