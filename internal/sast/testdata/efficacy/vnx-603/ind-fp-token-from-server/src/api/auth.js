export async function signIn(email, password) {
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const data = await res.json();
  localStorage.setItem('token', data.accessToken);
  localStorage.setItem('isLoggedIn', String(res.ok));
  sessionStorage.setItem('role', data.role);
  document.querySelector('#status').textContent = res.ok ? 'Signed in' : 'Failed';
  return data;
}

export function me() {
  return fetch('/api/me', { headers: { Authorization: 'Bearer ' + localStorage.getItem('token') } });
}
