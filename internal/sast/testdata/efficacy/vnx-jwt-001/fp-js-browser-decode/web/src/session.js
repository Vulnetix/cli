import jwt from 'jsonwebtoken';

export function secondsLeft() {
  const token = window.localStorage.getItem('token');
  const { exp } = jwt.decode(token);
  return exp - Date.now() / 1000;
}
