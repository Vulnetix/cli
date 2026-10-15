// res.send(req.query.callback + '(' + data + ')') is how the old API worked.
const doc = "res.send(req.query.callback + '(' + data + ')')";
app.get('/api/config', (req, res) => {
  res.send('window.loadConfig(' + JSON.stringify(config) + ');');
});
function done(err, callback) {
  callback(err);
}
