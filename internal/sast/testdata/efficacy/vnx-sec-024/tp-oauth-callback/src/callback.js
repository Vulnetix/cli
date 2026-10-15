export function handleCallback(tokens) {
  const params = new URLSearchParams(window.location.hash.slice(1));
  const accessToken = params.get("access_token");
~>  localStorage.setItem("access_token", accessToken);
~>  localStorage.setItem("id_token", params.get("id_token"));
~>  localStorage.setItem("auth", tokens.access_token);
~>  $window.localStorage.setItem(`oidc.refreshToken`, tokens.refreshToken);
  window.location.replace("/");
}
