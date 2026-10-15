package com.acme.pricing;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OfferTest {
    void equalsContract() {
        Offer o = new Offer();
        assertFalse(o.equals(null));
        assertTrue(o.compareTo(new Offer()) == 1);
    }
}
