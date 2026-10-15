package com.example.legacy;

import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;

@Controller("/export")
public class ExportController {

~>    @Deprecated
    @Get("/csv")
    public String csv() {
        return exporter.unescapedCsv();
    }
}
