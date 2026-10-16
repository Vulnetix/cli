import logging

logger = logging.getLogger(__name__)


def submit_application(applicant):
~>    logger.info("Applicant %s submitted, SSN %s", applicant.id, applicant.ssn)
    if applicant.date_of_birth > cutoff():
~>        logging.warning(
            "dob mismatch for %s: %s",
            applicant.id,
            applicant.date_of_birth,
        )
    return enqueue(applicant.id)
