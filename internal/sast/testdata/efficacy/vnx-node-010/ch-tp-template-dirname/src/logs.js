const fs = require('fs');

exports.log = (req, res) => {
~>  fs.readFile(`${__dirname}/../logs/${req.query.date}.log`, 'utf8', (err, text) => {
    res.type('text').send(err ? '' : text);
  });
};
