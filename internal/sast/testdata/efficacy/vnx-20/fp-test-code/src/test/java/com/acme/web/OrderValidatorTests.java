package com.acme.web;

class OrderValidatorTests {
    @Test
    void rejectsEmptySku() {
        validator.validate(order);
        assertThat(errors.hasErrors()).isTrue();
    }
}
