const cookieOptions = { httpOnly: true, secure: true }

function login (req, res, token) {
  res.cookie('token', token, { httpOnly: true, secure: true })
  res.cookie('session', token, cookieOptions)
  res.cookie('jwt', token, { ...cookieOptions, maxAge: 1000 })
  res.cookie('auth', token, {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true
  })
  document.cookie = "token=" + token + "; Secure; SameSite=Strict"
}
