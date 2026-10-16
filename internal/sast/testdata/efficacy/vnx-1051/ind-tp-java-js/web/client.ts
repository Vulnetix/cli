import axios from 'axios';
import net from 'net';

~>const API = 'http://10.0.4.12:8080/api';
export const http = axios.create({ baseURL: process.env.API_URL });
~>export const sock = net.connect(9000, '10.0.4.99');
