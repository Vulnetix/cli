package com.acme.auth;

import org.junit.jupiter.api.Test;

class FakeCredentialsTest {
    static class FakeCredentials implements Cloneable {
        private String password = "hunter2";

        @Override
        public FakeCredentials clone() throws CloneNotSupportedException {
            return (FakeCredentials) super.clone();
        }
    }

    @Test
    void clones() throws Exception {
        new FakeCredentials().clone();
    }
}
