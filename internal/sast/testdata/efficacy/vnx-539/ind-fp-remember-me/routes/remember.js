module.exports = function remember(app, tokens) {
  app.post('/login', async (req, res) => {
    const rememberToken = await tokens.rotate(req.user.id);
    res.cookie('remember_me', rememberToken, { maxAge: 30 * 24 * 3600 * 1000, httpOnly: true });
    res.redirect('/');
  });
};
