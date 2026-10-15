// Do not answer "User not found" here and "Wrong password" there:
// that difference lets an attacker enumerate accounts.
/*
 * return res.status(401).send('Unknown user');
 * return res.status(401).send('Invalid password');
 */
export async function login(req, res) {
  const ok = await auth.verify(req.body.user, req.body.password);
  if (!ok) return res.status(401).send('Login failed');
  res.redirect('/');
}
