export const PAYMENTS_API_URL = 'https://api.payments-provider.com/v1';

export async function refund(id: string) {
  return fetch(`${PAYMENTS_API_URL}/refunds/${id}`, { method: 'POST' });
}
