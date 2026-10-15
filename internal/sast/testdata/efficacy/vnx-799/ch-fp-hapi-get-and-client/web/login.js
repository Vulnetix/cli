import axios from 'axios';

const api = axios.create({ baseURL: '/api' });

export async function signIn(email, password) {
  const { data } = await api.post('/login', { email, password });
  return data;
}

export function routes(server) {
  server.route({
    method: 'GET',
    path: '/login',
    handler: (request, h) => h.view('login'),
  });
}

// router.route('/login').post(handler) used to live here before the move to SSO
const help = "POST /login with router.post('/login') to sign in";
