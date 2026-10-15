package com.example.api;

import @@sample:i[o][.]s[w]ag[g]er[.]v3[.]oa[s][.]a[n]no[t]at[i]on[s][.]O[p]er[a]ti[o]n@@;
import org.springframework.web.bind.annotation.*;

@RestController
public class SearchApi {

    @GetMapping("/search/raw")
    @Operation(
        summary = "Unfiltered search",
~>        deprecated = true)
    public List<Hit> raw(@RequestParam String q) {
        return index.rawQuery(q);
    }
}
