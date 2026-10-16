package bank;

import java.math.BigDecimal;
import java.util.Objects;
import java.util.UUID;

public class Ok {
    boolean a(Integer x, Integer y) { return x.equals(y); }
    boolean b(Long x, Long y) { return Objects.equals(x, y); }
    boolean c(BigDecimal x, BigDecimal y) { return x.compareTo(y) == 0; }
    boolean d(UUID x, UUID y) { return x.equals(y); }
}
