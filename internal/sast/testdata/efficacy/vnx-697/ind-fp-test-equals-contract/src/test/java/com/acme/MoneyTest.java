package com.acme;

import static org.junit.Assert.assertFalse;
import org.junit.Test;

public class MoneyTest {
    @Test
    public void equalsNull() {
        Money m = new Money(5);
        assertFalse(m.equals(null));
    }
}
