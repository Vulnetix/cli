const fs = require('fs');

module.exports = (req, res) => {
  // documents only: .pdf and .txt
  fs.writeFileSync(`uploads/${req.user.id}.pdf`, req.file.buffer);
  res.sendStatus(201);
};
