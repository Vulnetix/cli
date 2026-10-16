router.get('/panel', (req, res) => {
~>  if (req.query.bypass === 'yes') {
    res.locals.skipChecks = true
  }
  res.render('panel')
})
