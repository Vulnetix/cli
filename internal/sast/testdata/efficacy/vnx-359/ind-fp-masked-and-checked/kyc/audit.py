import logging

logger = logging.getLogger("kyc.audit")


def audit(applicant):
    logger.info("ssn on file: %s", mask(applicant.ssn))
    logger.info("ssn last four: %s", applicant.ssn[-4:])
    logger.info("ssn present: %s", applicant.ssn is not None)
    logger.info("passport digest %s", hashlib.sha256(applicant.passport_number.encode()).hexdigest())
    logger.info("dob redacted: %s", redact(applicant.date_of_birth))
