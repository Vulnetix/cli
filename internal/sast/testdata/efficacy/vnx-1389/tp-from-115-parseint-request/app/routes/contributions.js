// A radix-less parseInt of request data is reported by VNX-1389.
module.exports.update = (req, res) => {
~>  const preTax = parseInt(req.body.preTax);
  const { roth } = req.body;
~>  const rothPct = parseInt(roth);
  res.json({ preTax, rothPct });
};
