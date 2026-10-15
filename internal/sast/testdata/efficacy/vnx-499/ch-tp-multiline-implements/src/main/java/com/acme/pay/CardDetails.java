package com.acme.pay;

import java.io.Serializable;

public class CardDetails
        extends BaseEntity
        implements Serializable {

~>    private String cardNumber;
~>    private String cvv;
    private String holderName;
}
