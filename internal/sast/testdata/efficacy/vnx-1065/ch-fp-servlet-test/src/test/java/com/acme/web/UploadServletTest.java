package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

class UploadServletTest {
    @Test
    void concurrentUploads() throws Exception {
        Thread a = new Thread(() -> post("a"));
        Thread b = new Thread(() -> post("b"));
        a.start();
        b.start();
        a.join();
        b.join();
    }
}
