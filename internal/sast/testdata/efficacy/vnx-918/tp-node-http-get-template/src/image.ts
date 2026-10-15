import https from 'https';

export function thumb(req, res) {
  const host = req.params.host;
~>  https.get(`https://${host}/avatar.png`, (r) => r.pipe(res));
}
