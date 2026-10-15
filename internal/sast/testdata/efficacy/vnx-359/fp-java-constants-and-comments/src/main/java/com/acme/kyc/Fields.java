package com.acme.kyc;

public class Fields {
    public static final String SSN = "ssn";
    // log.info("ssn {}", customer.getSsn());
    void report(Customer c) {
        log.info("SSN present: {}", c.getSsn() != null);
        log.info("customer {} updated", c.getId());
        System.out.println("Enter date of birth:");
        repository.updateSsn(c.getId(), c.getSsn());
    }
}
