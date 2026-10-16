module.exports = function login(app, sessions) {
  app.post('/login', async (req, res) => {
    const sid = await sessions.create(req.body.username);
    res.cookie('sid', sid, { httpOnly: true, secure: true, sameSite: 'lax' });
    res.redirect('/');
  });
};
