// Old demo code did localStorage.setItem('isLoggedIn', 'true') after checking the password.
const HELP = "Never call localStorage.setItem('isAdmin', 'true') in the browser";

export function showHelp() {
  document.getElementById('help').textContent = HELP;
}
