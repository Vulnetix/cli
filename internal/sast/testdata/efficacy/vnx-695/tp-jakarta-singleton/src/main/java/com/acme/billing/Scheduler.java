package com.acme.billing;

import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;

@Singleton
@Startup
public class Scheduler {
    public void boot() {
~>        new Thread(this::loop, "billing-loop").start();
    }

    private void loop() {}
}
