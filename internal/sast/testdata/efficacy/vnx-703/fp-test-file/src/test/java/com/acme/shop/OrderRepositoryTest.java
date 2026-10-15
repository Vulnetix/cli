package com.acme.shop;

class OrderRepositoryTest {
    void saves() {
        Order saved = repo.findById(1L).get();
        assert saved != null;
    }
}
