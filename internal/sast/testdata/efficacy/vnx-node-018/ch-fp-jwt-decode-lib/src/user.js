import jwtDecode from 'jwt-decode';

export function displayName() {
  const token = localStorage.getItem('id_token');
  const claims = jwtDecode(token);
  return claims.name;
}
