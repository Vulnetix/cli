document.getElementById('go').addEventListener('click', () => {
  const pw = document.getElementById('pw').value;
  if (pw.length > 3) {
~>    localStorage.setItem('isLoggedIn', 'true');
    window.location = '/dashboard.html';
  }
});
