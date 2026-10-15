const PREFIX = "acme";

export function save(idToken, apiKey) {
~>  localStorage["id_token"] = idToken;
~>  localStorage.setItem(`${PREFIX}_api_key`, apiKey);
}
