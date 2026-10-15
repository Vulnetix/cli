export async function refresh() {
  const res = await fetch('/api/session', { credentials: 'include' });
  const data = await res.json();
  localStorage.setItem('isLoggedIn', String(data.authenticated));
  localStorage.setItem('lastSeen', new Date().toISOString());
  if (localStorage.getItem('theme') === 'dark') {
    document.body.classList.add('dark');
  }
}
