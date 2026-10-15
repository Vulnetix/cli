it('sets the session', () => {
  res.cookie('session', 'abc')
  app.use(session({ cookie: { secure: false } }))
})
