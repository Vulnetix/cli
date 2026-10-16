(function guard() {
  const role = sessionStorage.getItem('role');
~>  if (role !== 'admin') {
    window.location.replace('/login.html');
    return;
  }
  document.body.classList.remove('hidden');
})();
