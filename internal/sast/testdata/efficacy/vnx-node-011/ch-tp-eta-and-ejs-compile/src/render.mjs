import * as Eta from 'eta';
import ejs from 'ejs';

export function preview(req, res) {
  let src = 'Hello ' + req.body.greeting;
~>  const fn = ejs.compile(src, { client: false });
~>  const out = Eta.renderString(req.query.tpl, { site: 'x' });
  res.send(fn({}) + out);
}
