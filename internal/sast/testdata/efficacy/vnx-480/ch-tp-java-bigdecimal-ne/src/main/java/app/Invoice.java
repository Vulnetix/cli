package app;

import java.math.BigDecimal;

public class Invoice {
    private BigDecimal balance;

    boolean owesMoney() {
~>        return balance != BigDecimal.ZERO;
    }
}
