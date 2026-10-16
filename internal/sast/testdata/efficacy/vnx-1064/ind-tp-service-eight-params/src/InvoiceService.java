package billing;

import java.time.ZoneId;
import java.util.Locale;

public class InvoiceService {
~>    public Invoice create(String customer, String currency, long amount, int days,
                          boolean draft, Locale locale, ZoneId zone, String note) {
        return null;
    }
}
