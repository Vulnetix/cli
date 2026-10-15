export const config = {
~>  debug: process.env.APP_DEBUG || true,
~>  skipVerify: process.env.SKIP_TLS_VERIFY !== 'false',
~>  secureCookies: process.env.SECURE_COOKIES === 'true',
~>  tlsVerify: process.env['TLS_VERIFY'] ?? 'false',
};

~>const insecure = process.env.ALLOW_INSECURE || '1';
export default insecure;
