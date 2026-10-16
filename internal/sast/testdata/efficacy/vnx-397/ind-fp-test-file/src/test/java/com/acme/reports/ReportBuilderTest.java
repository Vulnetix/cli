package com.acme.reports;

import org.junit.jupiter.api.Test;

class ReportBuilderTest {
    @Test
    void buildsReport() throws Exception {
        new ReportBuilder(new InMemoryRepo()).build(1L);
    }
}
