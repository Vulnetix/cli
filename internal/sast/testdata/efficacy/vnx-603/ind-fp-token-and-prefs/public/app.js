async function login(user, pw) {
  const res = await fetch('/api/login', { method: 'POST', body: JSON.stringify({ user, pw }) });
  const data = await res.json();
  localStorage.setItem('token', data.accessToken);
  localStorage.setItem('theme', 'dark');
  localStorage.setItem('isLoggedIn', data.ok);
  localStorage.setItem('consent', 'true');
}

function logout() {
  localStorage.removeItem('isLoggedIn');
  localStorage.setItem('isLoggedIn', 'false');
  document.cookie = "loggedIn=false; path=/";
}

fetch('/api/me', { headers: { Authorization: 'Bearer ' + localStorage.getItem('token') } });
// localStorage.setItem('isLoggedIn', 'true');
const msg = "set isLoggedIn=true in localStorage";
