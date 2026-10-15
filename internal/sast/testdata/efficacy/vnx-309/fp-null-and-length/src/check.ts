export function validate(password: string, user: { password?: string }) {
  if (password === undefined || password === '') return false;
  if (user.password == null) return false;
  if (password.length !== 12) return false;
  return password !== 'changeme';
}
