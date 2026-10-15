export function persist(auth) {
~>  localStorage.token = auth.token;
~>  localStorage["auth_token"] = auth.token;
~>  window.localStorage['jwt'] = auth.jwt;
  localStorage.theme = "dark";
}
