function ContributionsHandler(db) {
  this.handleContributionsUpdate = (req, res, next) => {
~>    const preTax = eval(req.body.preTax);
~>    const afterTax = eval( req.body.afterTax );
    res.json({ preTax, afterTax });
  };
}
module.exports = ContributionsHandler;
