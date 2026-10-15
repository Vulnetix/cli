export function onLoginSubmit(form) {
  const user = form.username.value;
  if (user) {
~>    sessionStorage.setItem('role', 'admin');
    window.location.href = '/dashboard';
  }
}
