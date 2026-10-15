const path = require('path');
const fs = require('fs');

router.get('/download', (req, res) => {
~>  const name = req.query.file.split('../').join('');
  fs.createReadStream(path.join(__dirname, 'uploads', name)).pipe(res);
});

function stripScripts(html) {
~>  return html.replace(/<script\b[^>]*>([\s\S]*?)<\/script>/gi, '');
}
