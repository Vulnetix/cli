package com.acme.hr;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PayrollService {
    private static final Logger log = LoggerFactory.getLogger(PayrollService.class);

    public void onboard(Employee employee) {
~>        log.debug("Tax id for {} is {}", employee.getId(), employee.getTaxId());
        if (employee.isDriver()) {
~>            System.err.println("Driver licence: " + employee.getDriversLicenseNumber());
        }
        repository.save(employee);
    }

    public void admit(Patient patient) {
~>        log.info("Admitting patient {} MRN {}",
                patient.getName(),
                patient.getMedicalRecordNumber());
    }
}
