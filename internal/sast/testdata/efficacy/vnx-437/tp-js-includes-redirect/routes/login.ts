import { Router } from 'express';

const router = Router();

router.get('/login/done', (req, res) => {
  const returnTo = req.query.returnTo as string;
  if (returnTo.includes('acme.example.com')) {
~>    return res.redirect(returnTo);
  }
  if (returnTo.endsWith('.acme.example.com')) {
~>    res.redirect(302, returnTo);
    return;
  }
  res.redirect('/');
});

export default router;
