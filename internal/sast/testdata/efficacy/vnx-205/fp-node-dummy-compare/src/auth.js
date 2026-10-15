const bcrypt = require('bcrypt');
const DUMMY = '$2b$12$C6UzMDM.H6dfI/f/@@sample:I[K]cE[e]O5[q]Q8[s]VZ[K]Q3[o]3H[k]6x[1]jY[2]o8[b]0c[J]x4[m]3K@@';

async function login(req, res) {
  const user = await User.findOne({ email: req.body.email });
  const ok = await bcrypt.compare(req.body.password, user ? user.hash : DUMMY);
  if (!user || !ok) {
    return res.status(401).json({ error: 'Login failed' });
  }
  res.json({ token: sign(user) });
}
