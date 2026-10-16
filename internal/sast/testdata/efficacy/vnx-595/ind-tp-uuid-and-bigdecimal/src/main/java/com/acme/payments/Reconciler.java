package com.acme.payments;

import java.math.BigDecimal;
import java.util.UUID;

public class Reconciler {

    public boolean matches(Payment payment, Settlement settlement) {
        UUID paymentRef = payment.getReference();
        UUID settledRef = settlement.getPaymentReference();
        BigDecimal charged = payment.getAmount();
        BigDecimal settled = settlement.getAmount();
~>        if (paymentRef != settledRef) {
            return false;
        }
~>        return charged == settled;
    }
}
