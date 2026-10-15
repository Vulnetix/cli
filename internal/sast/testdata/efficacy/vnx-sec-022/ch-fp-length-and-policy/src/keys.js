function check(apiKey, passwordPolicy, tokenType) {
  console.log("api key length", apiKey.length);
  console.info("password policy", passwordPolicy);
  console.warn(`unexpected token type ${tokenType}`);
  console.log("Enter your password to continue");
  logger.error("invalid password for user %s", user.id);
}
