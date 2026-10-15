~>import { ENV } from '.';

export const timeoutMs = ENV === 'production' ? 5000 : 30000;
