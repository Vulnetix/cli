package com.acme.billing;

~>public class PaymentCard implements Comparable<PaymentCard>, Cloneable {
    private String holderName;
    private String cardNumber;
    private String cvv;
    private int expiryMonth;

    @Override
    public int compareTo(PaymentCard o) {
        return holderName.compareTo(o.holderName);
    }

    @Override
    public PaymentCard clone() throws CloneNotSupportedException {
        return (PaymentCard) super.clone();
    }
}
