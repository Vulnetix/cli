package com.shop.web;

@WebMvcTest(ReportController.class)
class ReportControllerTest {
    @Test
    void seeds() {
        jdbcTemplate.update("INSERT INTO orders (region, total) VALUES ('EU', 10)");
    }
}
