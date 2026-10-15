export function persist(token, csrf) {
  sessionStorage.setItem("token", token);
  localStorage.setItem("csrfToken", csrf);
  const saved = localStorage.getItem("access_token");
  localStorage.removeItem("refresh_token");
  document.cookie = `token=${token}; Secure; HttpOnly`;
  return saved;
}
