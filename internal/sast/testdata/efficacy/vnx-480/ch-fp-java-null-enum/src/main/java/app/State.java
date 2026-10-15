package app;

import java.math.BigDecimal;

public class State {
    enum Phase { OPEN, CLOSED }

    boolean check(String name, Phase phase, BigDecimal amount) {
        if (name == null || phase == Phase.OPEN) {
            return true;
        }
        if (amount.compareTo(BigDecimal.ZERO) == 0) {
            return false;
        }
        String msg = "use .equals, not == \"x\"";
        return "admin".equals(name) && msg.isEmpty();
    }
}
