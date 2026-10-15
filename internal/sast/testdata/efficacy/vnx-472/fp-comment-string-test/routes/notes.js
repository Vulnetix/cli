// Never trust req.body.price: look the product up instead.
/* const role = req.body.role; */
function explain(res) {
  res.send('the server ignores req.body.price and req.cookies.isAdmin');
}

module.exports = { explain };
