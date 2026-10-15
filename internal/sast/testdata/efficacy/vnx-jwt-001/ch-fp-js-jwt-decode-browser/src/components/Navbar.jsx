import { jwtDecode } from 'jwt-decode';

export function Navbar() {
  const token = localStorage.getItem('token');
  const user = token ? jwtDecode(token) : null;
  return <nav>{user ? user.name : 'Guest'}</nav>;
}
