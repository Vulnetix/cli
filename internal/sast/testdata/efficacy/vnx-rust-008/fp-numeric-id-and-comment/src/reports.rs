use axum::extract::Path;

pub async fn report(Path(id): Path<u64>) -> Vec<u8> {
    // Never do: base.join(&name) with a Path(name) extractor.
    let file = std::path::Path::new("/srv/reports").join(format!("{}.pdf", id));
    std::fs::read(file).unwrap_or_default()
}
