package com.acme.billing;

import jakarta.persistence.Embeddable;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import java.math.BigDecimal;

@Entity
public class Invoice extends BaseEntity {

    @Embedded
    private Money amount;

    private String number;
}

@Embeddable
record Money(BigDecimal value, String currency) {
}
