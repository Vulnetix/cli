package com.acme.boot;

import java.io.ObjectInputFilter;

public final class SerialFilterInit {
    private SerialFilterInit() {}

    public static void install() {
        ObjectInputFilter.Config.setSerialFilter(
                ObjectInputFilter.Config.createFilter("com.acme.**;java.base/*;!*"));
    }
}
