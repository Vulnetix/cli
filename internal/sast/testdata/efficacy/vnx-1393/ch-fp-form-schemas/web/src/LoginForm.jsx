export const fields = [
  { name: 'email', type: 'email', label: 'Email' },
  { name: 'password', type: 'password', autoComplete: 'current-password' },
];

export function PasswordInput() {
  return <input type="password" name="password" placeholder="Password" />;
}
