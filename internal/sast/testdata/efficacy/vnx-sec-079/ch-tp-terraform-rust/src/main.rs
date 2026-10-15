use octocrab::Octocrab;

async fn client() -> octocrab::Result<Octocrab> {
    Octocrab::builder()
~>        .personal_token("@@sample:github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}@@".to_string())
        .build()
}
