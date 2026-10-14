use std::path::{Path, PathBuf};

pub fn config_path(home: &Path, profile: &str) -> PathBuf {
    home.join(".config").join(profile)
}

pub fn assets() -> tower_http::services::ServeDir {
    tower_http::services::ServeDir::new("assets")
}

pub fn read_manifest(dir: &Path) -> std::io::Result<String> {
    std::fs::read_to_string(dir.join("Cargo.toml"))
}
