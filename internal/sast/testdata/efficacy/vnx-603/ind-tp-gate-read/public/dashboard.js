window.addEventListener('DOMContentLoaded', () => {
~>  if (localStorage.getItem('isLoggedIn') !== 'true') {
    window.location.href = '/login.html';
  }
  document.getElementById('app').hidden = false;
});
