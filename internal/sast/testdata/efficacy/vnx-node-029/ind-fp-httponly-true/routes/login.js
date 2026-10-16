module.exports = function (app) {
  app.post('/login', (req, res) => {
    res.cookie('session', req.sid, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
    });
    res.cookie('sid2', req.sid, cookieOpts);
    res.send('ok');
  });
};
const cookieOpts = { httpOnly: true, secure: true };
