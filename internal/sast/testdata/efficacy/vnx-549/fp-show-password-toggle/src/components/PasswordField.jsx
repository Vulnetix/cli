export function PasswordField({ visible }) {
  return <input type={visible ? 'text' : 'password'} name="password" />;
}
