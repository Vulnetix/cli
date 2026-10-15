// Never call ejs.render(req.body.template) with user input.
const warning = 'pug.compile(req.query.tpl) is server-side template injection';
module.exports = { warning };
