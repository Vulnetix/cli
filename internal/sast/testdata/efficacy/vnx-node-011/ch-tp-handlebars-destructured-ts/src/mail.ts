import Handlebars from 'handlebars';

export function renderMail(req: any, res: any) {
  const { template } = req.body;
~>  const fn = Handlebars.compile(template);
  res.send(fn({ name: 'there' }));
}
