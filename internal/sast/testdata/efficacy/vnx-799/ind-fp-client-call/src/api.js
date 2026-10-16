import axios from 'axios';

export async function signIn(email, password) {
  const res = await axios.post('/login', { email, password });
  return res.data;
}
export const refresh = () => api.post('/token/refresh');
