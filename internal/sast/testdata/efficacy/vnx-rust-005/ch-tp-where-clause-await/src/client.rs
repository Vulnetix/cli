use serde::de::DeserializeOwned;

pub async fn fetch<T>(url: &str) -> Result<T, reqwest::Error>
where
    T: DeserializeOwned,
{
~>    let resp = reqwest::get(url).await.unwrap();
    resp.json::<T>().await
}

pub async fn fetch_text(client: &reqwest::Client, url: &str) -> eyre::Result<String> {
    let body = client
        .get(url)
        .send()
        .await
~>        .expect("request failed");
    Ok(body.text().await?)
}
