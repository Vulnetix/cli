package com.acme.user;

import org.junit.jupiter.api.Test;

class UserRepositoryTest {

    @Test
    void findsSaved() {
        User u = repo.findById(1L).get();
        assert u != null;
    }
}
