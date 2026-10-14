// Never pass ejs.render(req.body.template) a user-supplied template.
/* pug.render(req.query.tpl) compiles attacker input */
const hint = 'Handlebars.compile(req.body.layout) is template injection';
module.exports = { hint };
