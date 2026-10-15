export function boot(cfg: { secretArn: string; secretsManagerRegion: string; tokenEndpoint: string }) {
  logger.info('loading secret', cfg.secretArn);
  console.log('secrets manager region', cfg.secretsManagerRegion);
  logger.debug('token endpoint', cfg.tokenEndpoint);
}
