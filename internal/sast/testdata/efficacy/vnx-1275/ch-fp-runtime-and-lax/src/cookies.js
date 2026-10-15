const isEmbed = process.env.EMBED_MODE === '1';

function setSession(res, sid) {
  res.cookie('sid', sid, {
    httpOnly: true,
    secure: true,
    sameSite: isEmbed ? 'none' : 'lax',
  });
}

function validate(opts) {
  if (opts.sameSite === 'none' && !opts.secure) {
    throw new Error("sameSite: 'none' requires secure");
  }
  switch (opts.sameSite) {
    case 'none':
      return 'cross-site';
    default:
      return 'same-site';
  }
}

module.exports = { setSession, validate };
