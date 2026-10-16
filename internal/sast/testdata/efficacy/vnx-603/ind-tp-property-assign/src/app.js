const loginButton = document.getElementById('login');

loginButton.addEventListener('click', async () => {
  await showWelcome();
~>  sessionStorage.isAdmin = true;
  document.querySelector('nav .admin').classList.add('visible');
});

~>if (localStorage.getItem('isAuthenticated') === 'true') {
  document.body.dataset.state = 'signed-in';
}
