// JSON.parse(Buffer.from(req.cookies.session, 'base64')) trusts the client
const hint = "never JSON.parse(atob(req.query.state)) without a signature";
