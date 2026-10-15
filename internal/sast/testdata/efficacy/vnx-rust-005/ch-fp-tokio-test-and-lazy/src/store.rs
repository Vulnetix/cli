use once_cell::sync::Lazy;
use regex::Regex;

static KEY: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z0-9_]{1,64}$").unwrap());

pub async fn get(key: &str) -> Result<Option<String>, std::io::Error> {
    if !KEY.is_match(key) {
        return Ok(None);
    }
    let v = tokio::fs::read_to_string(format!("/data/{key}")).await?;
    Ok(Some(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_value() -> Result<(), std::io::Error> {
        let v = get("alpha").await.unwrap();
        assert!(v.is_none());
        Ok(())
    }
}
