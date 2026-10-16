app.use((req, res, next) => {
~>  const session = JSON.parse(Buffer.from(req.cookies.session, 'base64').toString());
  req.session = session;
  next();
});
