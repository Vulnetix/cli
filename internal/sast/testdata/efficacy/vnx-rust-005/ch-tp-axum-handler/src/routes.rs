use axum::{extract::State, response::IntoResponse, Json};
use sqlx::PgPool;

pub async fn list_users(State(pool): State<PgPool>) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query_as::<_, User>("SELECT id, name FROM users")
        .fetch_all(&pool)
~>        .await.unwrap();
    Ok(Json(rows))
}

pub async fn create(State(pool): State<PgPool>, body: String) -> Result<Json<User>, AppError> {
~>    let input: NewUser = serde_json::from_str(&body).expect("valid body");
    let user = insert(&pool, input).await?;
    Ok(Json(user))
}
