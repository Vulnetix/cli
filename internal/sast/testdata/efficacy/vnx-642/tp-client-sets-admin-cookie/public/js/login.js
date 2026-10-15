async function onLogin(form) {
  const res = await fetch('/api/login', { method: 'POST', body: new FormData(form) });
  const body = await res.json();
~>  document.cookie = "isAdmin=" + body.admin + "; path=/";
~>  document.cookie = `role=${body.role}; path=/`;
  document.cookie = "theme=dark; path=/";
}
