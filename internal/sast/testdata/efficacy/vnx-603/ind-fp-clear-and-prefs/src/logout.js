export function logout() {
  localStorage.removeItem('isLoggedIn');
  sessionStorage.setItem('isAdmin', 'false');
  document.cookie = 'loggedIn=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
  window.location.href = '/';
}

export function savePrefs() {
  localStorage.setItem('theme', 'dark');
  localStorage.setItem('cookieConsent', 'true');
  document.body.classList.toggle('dark');
}
