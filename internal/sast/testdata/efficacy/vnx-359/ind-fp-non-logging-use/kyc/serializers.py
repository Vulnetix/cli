def to_record(applicant):
    db.save(applicant.ssn)
    return {
        "id": applicant.id,
        "ssn": encrypt(applicant.ssn),
        "date_of_birth": applicant.date_of_birth.isoformat(),
    }
