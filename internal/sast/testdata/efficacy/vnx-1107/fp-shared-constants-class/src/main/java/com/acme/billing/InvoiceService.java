package com.acme.billing;

import com.acme.common.Limits;

public class InvoiceService {
    private static final int BATCH = Limits.MAX_RETRIES * 2;
}
