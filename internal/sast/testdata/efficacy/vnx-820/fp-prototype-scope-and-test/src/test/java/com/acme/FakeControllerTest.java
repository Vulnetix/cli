package com.acme;

import org.springframework.web.bind.annotation.RestController;

@RestController
class FakeControllerTest {
    private int calls;

    void handle() {
        calls++;
    }
}
