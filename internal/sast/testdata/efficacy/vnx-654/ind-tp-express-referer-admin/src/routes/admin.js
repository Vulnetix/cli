router.get('/admin', (req, res) => {
~>  if (req.headers['referer'].startsWith('https://intranet.example.com')) {
    req.session.isAdmin = true
    return res.render('admin')
  }
  res.status(403).end()
})
