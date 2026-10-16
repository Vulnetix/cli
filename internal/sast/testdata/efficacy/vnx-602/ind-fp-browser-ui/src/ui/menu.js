function renderMenu(user) {
  if (user.role === 'admin') {
    showAdminLink();
  }
}
