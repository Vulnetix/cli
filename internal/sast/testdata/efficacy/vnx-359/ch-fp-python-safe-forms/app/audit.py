import logging

logger = logging.getLogger(__name__)


def audit(user, record, request_id):
    logger.info("SSN updated for user %s", user.id)
    logger.info("dob verified: %s", user.dob_verified)
    logger.info("ssn=%s", mask_ssn(user.ssn))
    logger.info("ssn_present=%s", bool(record.ssn))
    logger.error("invalid ssn format for request %s", request_id)
    logger.info("passport last four %s", record.passport_number[-4:])
    print("Enter your date of birth:")
