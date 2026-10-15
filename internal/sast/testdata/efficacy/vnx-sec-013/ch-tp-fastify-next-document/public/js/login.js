async function login(form) {
  const res = await fetch('/api/login', { method: 'POST', body: new FormData(form) });
  const { token } = await res.json();
~>  document.cookie = `auth_token=${token}; path=/; max-age=86400`;
~>  document.cookie = "sessionid=" + res.headers.get('X-Session') + "; path=/";
}
