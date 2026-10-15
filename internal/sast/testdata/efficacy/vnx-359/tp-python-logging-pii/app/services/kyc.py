import logging

logger = logging.getLogger(__name__)


def register(applicant):
~>    logger.info("registering applicant %s ssn=%s", applicant.name, applicant.ssn)
~>    logging.debug(f"passport {applicant.passport_number} dob {applicant.date_of_birth}")
    social_security_number = applicant.raw["ssn"]
~>    print("SSN:", social_security_number)
~>    self_log = logger.warning(
        "failed check for %s", applicant.national_id
    )
