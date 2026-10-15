function storeToken(token) {
~>  document.cookie = "access_token=" + token + "; path=/";
~>  document.cookie = `sessionId=${token}; max-age=3600`;
}
