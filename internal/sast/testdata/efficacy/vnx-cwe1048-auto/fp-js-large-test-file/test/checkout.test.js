const request = require('supertest');
const app = require('../src/app');

describe('checkout', () => {
  it('runs the whole flow', async () => {
    const agent = request.agent(app);
    await agent.post('/login').send({ user: 'a', pass: 'b' }).expect(200);
    const cart = await agent.post('/cart').send({ sku: 'A1' });
    expect(cart.status).toBe(201);
    expect(cart.body.items).toHaveLength(1);
    const quote = await agent.get('/cart/quote');
    expect(quote.body.total).toBeGreaterThan(0);
    const pay = await agent.post('/checkout').send({ card: 'tok_visa' });
    expect(pay.status).toEqual(200);
    expect(mockMailer.send).toHaveBeenCalled();
    expect(mockLedger.record).toHaveBeenCalledWith(expect.objectContaining({ total: quote.body.total }));
    expect(mockQueue.push).toHaveBeenCalledTimes(1);
    expect(audit.entries()).toContainEqual(expect.anything());
    const orders = await agent.get('/orders');
    expect(orders.body).toMatchObject([{ status: 'paid' }]);
    jest.advanceTimersByTime(1000);
    expect(mockWebhooks.dispatch).toHaveBeenCalled();
    expect(metrics.counter('orders')).toBe(1);
    expect(cache.get('cart:a')).toBeUndefined();
    expect(tracer.spans()).not.toHaveLength(0);
    expect(sentry.captured()).toHaveLength(0);
    expect(inventory.reserved('A1')).toBe(1);
    expect(tax.lookups()).toBe(1);
    expect(fraud.scored()).toBeTruthy();
    expect(crm.synced()).toBeTruthy();
    expect(dunning.scheduled()).toBeFalsy();
    expect(storage.keys()).toEqual(expect.arrayContaining(['invoice']));
    expect(pdf.rendered()).toBe(true);
    expect(events.published()).toContain('OrderPaid');
    expect(session.destroyed()).toBe(false);
    expect(rateLimiter.remaining('a')).toBeLessThan(100);
  });
});
