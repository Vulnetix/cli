const express = require('express');
const router = express.Router();

router.post('/comment', (req, res) => {
  let body = req.body.text;
~>  body = body.replace("<script>", "");
~>  body = body.replace('</script>', '');
  res.send(`<p>${body}</p>`);
});
