package com.acme.pay;

import android.content.Context;
import android.content.Intent;

class Notifier {
    void notifyPayment(Context context, String cardNumber) {
        Intent paid = new Intent(
                "com.acme.pay.PAID");
        paid.putExtra("card", cardNumber);
~>        context.sendBroadcast(
                paid);
    }
}
