exports.handoff = (req, res) => {
~>  res.redirect(`${req.query.host}/welcome`);
};
