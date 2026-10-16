package com.acme;

import android.content.Context;
import android.content.Intent;

class Order {
    void fire(Context c, String id) {
~>        c.sendOrderedBroadcast(new Intent("com.acme.ORDER_PLACED").putExtra("id", id), null);
    }
}
