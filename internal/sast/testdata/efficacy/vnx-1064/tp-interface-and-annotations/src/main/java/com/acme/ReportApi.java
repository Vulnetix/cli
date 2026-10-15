package com.acme;

public interface ReportApi {
~>    Report build(@Param("from, to") String from, @Param("to") String to, @Nullable String region,
            int page, int size, String sort, boolean desc, String format);

    @GetMapping("/reports")
~>    default String render(@RequestParam("a") String a, @RequestParam("b") String b, @RequestParam("c") String c, @RequestParam("d") String d, @RequestParam("e") String e, @RequestParam("f") String f, @RequestParam("g") String g, @RequestParam("h") String h) {
        return a;
    }
}
