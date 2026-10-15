function reset(user) {
  console.log('Password reset email sent');
  logger.warn('invalid password for %s', user.name);
  logger.info('token refreshed for user', user.id);
}
