export function markAdmin() {
~>  document.cookie = 'role=admin; path=/; max-age=3600';
  document.querySelector('#admin-link').hidden = false;
}

export function markLoggedIn(name) {
  document.querySelector('#greeting').textContent = `Hi ${name}`;
~>  document.cookie = "loggedIn=true; path=/; SameSite=Lax";
}
