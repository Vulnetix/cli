package com.example;

import android.content.SharedPreferences;
import org.junit.Test;

public class GateTest {
    @Test
    public void restoresFlag() {
        SharedPreferences prefs = mock(SharedPreferences.class);
        boolean v = prefs.getBoolean("isLoggedIn", false);
        assertFalse(v);
    }
}
