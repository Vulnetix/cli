import jwtDecode from 'jwt-decode';

export function useUser(token) {
  const user = jwtDecode(token);
  return user.name;
}
