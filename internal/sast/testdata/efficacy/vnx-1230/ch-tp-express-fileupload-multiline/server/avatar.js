const express = require('express');
const fileUpload = require('express-fileupload');
const path = require('path');

const app = express();
app.use(fileUpload({ limits: { fileSize: 2 * 1024 * 1024 } }));

app.post('/account/avatar', (req, res) => {
  const avatar = req.files && req.files.avatar;
  if (!avatar || !/^image\//.test(avatar.mimetype)) {
    return res.status(400).send('image required');
  }
  const dest = path.join(__dirname, 'public', 'avatars', req.session.uid + '.png');
~>  avatar.mv(
    dest,
    (err) => (err ? res.status(500).end() : res.redirect('/account'))
  );
});

module.exports = app;
