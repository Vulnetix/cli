export async function login(creds: Creds) {
  const res = await api.post("/login", creds);
~>  localStorage.setItem("access_token", res.data.access_token);
~>  localStorage.setItem('refreshToken', res.data.refreshToken);
  return res.data.user;
}
