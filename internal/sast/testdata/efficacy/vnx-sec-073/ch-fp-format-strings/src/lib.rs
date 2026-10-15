pub fn remote(user: &str, token: &str) -> String {
    format!("https://{}:{}@git.acme-corp.io/platform/infra.git", user, token)
}
