import express from 'express';
import * as security from './security';

const app = express();
app.post('/rest/2fa/setup',
  security.isAuthorized(),
  security.isAuthorized(),
  twoFactor.setup);
const name = user && user.profile && user.profile.name;
export default app;
