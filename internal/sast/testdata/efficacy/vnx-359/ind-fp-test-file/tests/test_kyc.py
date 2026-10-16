from kyc.services import submit_application


def test_submit(applicant_factory, caplog):
    applicant = applicant_factory(ssn="078-05-1120")
    print("using ssn", applicant.ssn)
    submit_application(applicant)
    assert "submitted" in caplog.text
