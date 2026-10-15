import axios from 'axios';

~>const API_BASE_URL = 'http://api.acme-corp.com';

export function getUser(id) {
  return axios.get(`${API_BASE_URL}/users/${id}`);
}
