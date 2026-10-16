package com.acme;
import org.junit.Test;
public class LoaderTest {
    @Test public void t() {
        try { new Loader().load(null); } catch (Exception e) {}
        try {
            Thread.sleep(1);
        } catch (InterruptedException e) {
        }
    }
}
