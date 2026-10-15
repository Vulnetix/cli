import logging

logger = logging.getLogger(__name__)


def submit(user, data, patient):
~>    logger.info("user %s ssn %s", user.email_hash, user.ssn)
~>    logger.warning("payload ssn=%s", data["ssn"])
~>    logging.debug("Created patient %s", patient.medical_record_number)
    logger.info(
        "applicant created id=%s",
        user.id,
    )
~>    logger.info(
        "applicant %s born %s",
        user.id,
        user.date_of_birth,
    )
