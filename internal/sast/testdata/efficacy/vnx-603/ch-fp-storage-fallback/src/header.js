export function headerRole(props) {
  const role = props.role || localStorage.getItem('role');
  document.title = `Signed in as ${role}`;
  return role;
}
