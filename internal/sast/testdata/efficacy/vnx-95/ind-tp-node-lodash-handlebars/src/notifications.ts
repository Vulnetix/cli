import _ from 'lodash';
import Handlebars from 'handlebars';
import ejs from 'ejs';
import { Router } from 'express';

export const notifications = Router();

notifications.post('/notifications/preview', (req, res) => {
  const message = req.body.message;
~>  const compiled = _.template(message);
  res.send(compiled({ user: req.user }));
});

notifications.post('/notifications/card', (req, res) => {
~>  const card = Handlebars.compile(`<div class="card">${req.body.html}</div>`);
  res.send(card({}));
});

notifications.get('/notifications/raw', (req, res) => {
~>  res.send(ejs.render(String(req.query.tpl), {}));
});
