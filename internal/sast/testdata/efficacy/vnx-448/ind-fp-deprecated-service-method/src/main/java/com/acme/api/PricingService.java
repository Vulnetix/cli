package com.acme.api;

import java.math.BigDecimal;
import org.springframework.stereotype.Service;

@Service
public class PricingService {

    @Deprecated
    public BigDecimal priceWithoutTax(Product p) {
        return p.getBasePrice();
    }

    @Deprecated(since = "4.0", forRemoval = true)
    public static final String LEGACY_CURRENCY = "USD";

    public BigDecimal price(Product p, TaxRule rule) {
        return rule.apply(p.getBasePrice());
    }
}
