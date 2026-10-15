use axum::extract::Query;
use std::path::Path;

#[derive(serde::Deserialize)]
pub struct DocQuery {
    page: String,
}

pub async fn doc(Query(q): Query<DocQuery>) -> Result<String, std::io::Error> {
    let root = Path::new("docs");
    let text = tokio::fs::read_to_string(
~>        root.join(&q.page),
    )
    .await?;
    Ok(text)
}
