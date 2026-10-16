// Never pass { ignoreExpiration: true } to jwt.verify; see SECURITY.md.
const HELP = 'options={"verify_exp": False} disables expiry checks';

module.exports = { HELP };
