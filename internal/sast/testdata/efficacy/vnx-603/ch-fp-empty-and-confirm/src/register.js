export function validate(form) {
  const password = form.password.value;
  const confirm = form.confirm.value;
  if (password === '' || password !== confirm) {
    return 'Passwords must match';
  }
  if (password.length < 12) {
    return 'Too short';
  }
  return null;
}
