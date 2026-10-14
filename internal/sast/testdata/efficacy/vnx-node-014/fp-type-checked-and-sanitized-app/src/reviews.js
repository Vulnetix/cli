const db = require('./db');

function updateReview(req, res) {
  if (typeof req.body.id !== 'string') {
    return res.status(400).end();
  }
  return db.reviews.updateOne({ _id: req.body.id }, { $set: { message: req.body.message } })
    .then((r) => res.json(r));
}

module.exports = { updateReview };
