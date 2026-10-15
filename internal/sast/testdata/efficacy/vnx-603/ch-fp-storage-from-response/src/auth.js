export async function login(creds) {
  const res = await fetch('/api/login', { method: 'POST', body: JSON.stringify(creds) });
  const data = await res.json();
  localStorage.setItem('auth', JSON.stringify(data));
  sessionStorage.setItem('role', data.role);
  const pin = document.getElementById('pin').value;
  if (pin.length === 4 && creds.password === creds.confirmPassword) {
    return data;
  }
}
