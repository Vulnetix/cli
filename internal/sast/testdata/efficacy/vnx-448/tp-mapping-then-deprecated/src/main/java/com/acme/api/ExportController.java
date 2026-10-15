package com.acme.api;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1")
public class ExportController {

    @GetMapping("/export.xls")
    @ResponseBody
~>    @Deprecated(since = "3.2", forRemoval = true)
    public byte[] exportXls(@RequestParam String account) {
        return legacyExporter.xls(account);
    }
}
