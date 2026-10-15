import logging


def receive(claim):
    patient = claim.patient
~>    logging.getLogger(__name__).info("intake for %s born %s", patient.name, patient.date_of_birth)
~>    logging.getLogger("claims.audit").warning(
        "mismatch on medical record %s", claim.medical_record_number
    )
    return claim.id
