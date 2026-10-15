package com.acme;

class RepoTest {
    void loads() {
        try {
            repo.find(1);
        } catch (Exception e) {
            fail();
        }
    }
}
