async function login(form) {
  const res = await fetch('/api/login', { method: 'POST', body: new FormData(form) });
  const { token } = await res.json();
  // Reported by VNX-1004 (a cookie without HttpOnly), not by this rule.
  document.cookie = `auth_token=${token}; path=/; max-age=86400`;
  // Reported by VNX-1004 (a cookie without HttpOnly), not by this rule.
  document.cookie = "sessionid=" + res.headers.get('X-Session') + "; path=/";
}
