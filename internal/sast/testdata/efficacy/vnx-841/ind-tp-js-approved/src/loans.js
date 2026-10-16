app.post('/loans/:id/approve', async (req, res) => {
  const loan = await Loan.findById(req.params.id);
~>  loan.approved = req.body.approved;
  await loan.save();
  res.json(loan);
});
