export function startLogin(): void {
  const clientId = "spa-client";
~>  const authorizeUrl = "https://auth.example.com/oauth2/authorize?response_type=code&client_id=spa-client&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&state=af0ifjsldkj";
  window.location.assign(authorizeUrl);
}
