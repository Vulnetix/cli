import axios from "axios";

~>const BASE_URL = 'https://10.44.0.9/api/v2';

export const client = axios.create({
  baseURL: BASE_URL,
  timeout: 3000,
});

export const mq = {
~>  brokers: ["10.44.0.21:9092"],
};
