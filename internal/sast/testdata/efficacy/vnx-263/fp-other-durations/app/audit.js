function tooOld(user) {
  return user.passwordAgeDays > 365;
}
const ARCHIVE_DAYS = 400;
module.exports = { tooOld, ARCHIVE_DAYS };
