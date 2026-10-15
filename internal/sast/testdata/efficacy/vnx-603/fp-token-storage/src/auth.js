export function onLoginResponse(res) {
  localStorage.setItem('token', res.accessToken);
  localStorage.setItem('isLoggedIn', String(res.ok));
  const token = localStorage.getItem('token');
  if (!token) {
    return redirectToLogin();
  }
  return fetch('/api/me', { headers: { Authorization: 'Bearer ' + token } });
}

export function logout() {
  localStorage.removeItem('isLoggedIn');
  localStorage.setItem('isLoggedIn', 'false');
}
