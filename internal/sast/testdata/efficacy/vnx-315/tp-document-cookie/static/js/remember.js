function remember(user, pwd) {
~>  document.cookie = "password=" + pwd + "; path=/";
~>  document.cookie = `user=${user}:${pwd}`;
  document.cookie = "theme=dark";
}
