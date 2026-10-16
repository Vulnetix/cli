package fin;

import java.math.BigDecimal;
import java.util.Date;

public class Money {
    boolean equalAmounts(BigDecimal left, BigDecimal right) {
~>        return left == right;
    }

    boolean sameDay(Date a, Date b) {
~>        return a == b;
    }
}
