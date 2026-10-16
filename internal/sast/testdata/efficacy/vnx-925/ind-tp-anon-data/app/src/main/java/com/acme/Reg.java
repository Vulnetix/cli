package com.acme;
public class Reg {
    BroadcastReceiver r = new BroadcastReceiver() {
        @Override
~>        public void onReceive(Context c, Intent i) {
            Uri u = i.getData();
            open(u);
        }
    };
}
