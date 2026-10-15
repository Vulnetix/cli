// Never write Object.assign(req.session, req.body): it lets the client set any session field.
const HELP = "Object.assign(req.user, req.body) copies every field the client sends";
