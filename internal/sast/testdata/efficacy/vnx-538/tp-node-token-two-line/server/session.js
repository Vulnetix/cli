const fs = require('fs');
const path = require('path');

function persistSession(req) {
  const out = path.join(__dirname, 'static', 'sessions', `${req.session.id}.txt`);
~>  fs.writeFile(out, req.session.accessToken, (err) => {
    if (err) console.error(err);
  });
}
