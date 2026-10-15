export const featureFlags = {
~>  betaAdmin: Boolean(process.env['BETA_ADMIN']),
  region: process.env.REGION || 'eu-west-1',
};
