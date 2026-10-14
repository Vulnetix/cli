import express from 'express';
import helmet from 'helmet';
import request from 'supertest';

describe('frame headers', () => {
  it('reports the header the app sets', async () => {
    const app = express();
    app.use(helmet({ frameguard: false }));
    app.get('/', (_req, res) => {
      res.setHeader('X-Frame-Options', 'ALLOWALL');
      res.send('ok');
    });
    const res = await request(app).get('/');
    expect(res.headers['x-frame-options']).toBe('ALLOWALL');
  });
});
