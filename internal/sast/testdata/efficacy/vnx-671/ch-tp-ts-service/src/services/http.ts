import axios from 'axios';

~>process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

export const api = axios.create({ baseURL: 'https://internal.example' });
