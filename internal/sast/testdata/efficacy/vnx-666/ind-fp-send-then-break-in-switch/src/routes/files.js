const path = require('path');

function serve(req, res, kind) {
  switch (kind) {
    case 'pdf':
      res.sendFile(path.join(__dirname, 'doc.pdf'));
      break;
    case 'zip':
      res.download(path.join(__dirname, 'bundle.zip'));
      break;
    default:
      res.status(400).send('unknown kind');
  }
}

module.exports = { serve };
