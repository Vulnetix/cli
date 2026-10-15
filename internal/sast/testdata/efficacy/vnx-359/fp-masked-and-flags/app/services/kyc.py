import logging

logger = logging.getLogger(__name__)


def register(applicant):
    logger.info("ssn on file: %s", mask(applicant.ssn))
    logger.info("ssn last4=%s", applicant.ssn[-4:] if False else applicant.ssn_last4)
    logger.info("has passport: %s", applicant.has_passport)
    logger.info("Collecting SSN and date of birth for applicant %s", applicant.id)
    # logger.info("ssn=%s", applicant.ssn)
    print("Please enter your passport number")
    logger.debug("ssn hash %s", hashlib.sha256(applicant.ssn.encode()).hexdigest())
    db.save(ssn=applicant.ssn)
