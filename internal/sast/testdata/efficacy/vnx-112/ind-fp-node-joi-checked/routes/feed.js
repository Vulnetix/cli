const Joi = require('joi');
const xml2js = require('xml2js');

const feedSchema = Joi.object({
  feed: Joi.object({
    entry: Joi.array().items(Joi.object({ id: Joi.string().required() })).required(),
  }).required(),
});

module.exports = (app) => {
  app.post('/feed', (req, res) => {
    xml2js.parseString(req.body, (err, result) => {
      if (err) return res.status(400).end();
      const { error, value } = feedSchema.validate(result);
      if (error) return res.status(422).json({ error: error.message });
      res.json({ count: value.feed.entry.length });
    });
  });
};
