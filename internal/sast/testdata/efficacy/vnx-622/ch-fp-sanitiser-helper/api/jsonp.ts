import { sanitizeCallbackName } from './util';

export function feed(req, res) {
  const cb = sanitizeCallbackName(req.query.callback);
  res.type('application/javascript');
  res.send(`${cb}(${JSON.stringify(loadFeed())})`);
}
