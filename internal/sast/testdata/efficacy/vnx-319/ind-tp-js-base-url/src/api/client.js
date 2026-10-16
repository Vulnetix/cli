import axios from 'axios';

~>export const INVENTORY_BASE_URL = 'http://api.inventory-hub.net/v2';

export const client = axios.create({ baseURL: INVENTORY_BASE_URL, timeout: 5000 });
