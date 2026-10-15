package com.acme.root;

import org.junit.Before;

public class DeviceSetupTest {
    @Before
    public void grant() throws Exception {
        Runtime.getRuntime().exec(new String[] {"su", "-c", "pm grant com.acme android.permission.READ_LOGS"}).waitFor();
    }
}
