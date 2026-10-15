function compare(fromDB, fromUser) {
  return fromDB === fromUser;
  /*
  // stronger comparison, disabled
  return bcrypt.compareSync(fromDB, fromUser);
  */
}
