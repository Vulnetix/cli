const logger = require("./logger");

function report(applicant) {
  console.log("ssn last4", applicant.ssn.slice(-4));
  logger.info("has passport", Boolean(applicant.passportNumber));
  logger.info({ applicantId: applicant.id, ssnProvided: !!applicant.ssn });
  logger.debug("dob hash", sha256(applicant.dateOfBirth));
}
module.exports = { report };
