const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

function respond(req, res, data) {
  const format = req.query.format;
  if (format === 'html') {
    return res.send(renderHtml(data));
  }
  if (req.query.lang === 'js') {
    return res.json(data);
  }
  return res.send(data);
}

module.exports = { upload, respond };
