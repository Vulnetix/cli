package com.shop;

class CsvExporterTest {
    void builds() {
        String expected = "";
        for (String name : names) {
            expected += name + ",";
        }
    }
}
