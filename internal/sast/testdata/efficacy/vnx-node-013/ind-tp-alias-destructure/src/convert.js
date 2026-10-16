const cp = require('child_process');

app.post('/thumb', (req, res) => {
  const { file } = req.query;
~>  cp.exec(`convert ${file} -resize 64x64 thumb.png`, (err) => {
    res.sendStatus(err ? 500 : 200);
  });
});
