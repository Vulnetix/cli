pub async fn fetch_user(
    pool: &sqlx::PgPool,
    id: i64,
) -> Result<User, sqlx::Error> {
    let row = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
~>        .unwrap();
    Ok(row)
}

pub fn port() -> anyhow::Result<u16> {
~>    let p = std::env::var("PORT").unwrap();
    Ok(p.len() as u16)
}
