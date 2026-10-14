pub type Result<T> = std::result::Result<T, Error>;

pub async fn fetch(
    client: &reqwest::Client,
    url: &str,
) -> std::result::Result<bytes::Bytes, reqwest::Error> {
~>    let resp = client.get(url).send().await.unwrap();
    resp.bytes().await
}

impl Store {
    pub fn get(&self, key: &str) -> Result<String> {
        let conn = self.pool.get()?;
~>        let row = conn.query_row(key).expect("row exists");
        Ok(row)
    }
}
