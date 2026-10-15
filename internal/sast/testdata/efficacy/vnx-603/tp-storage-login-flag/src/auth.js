export function onLoginResponse(ok) {
  if (ok) {
~>    localStorage.setItem('isLoggedIn', 'true');
~>    sessionStorage.setItem("isAdmin", true);
  }
}

export function guard(router) {
~>  if (localStorage.getItem('isLoggedIn') !== 'true') {
    router.push('/login');
  }
~>  const admin = sessionStorage.getItem('isAdmin') === 'true';
  return admin;
}
