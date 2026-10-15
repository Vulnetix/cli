package com.acme.api;

import @@sample:i[o][.]s[w]ag[g]er[.]v3[.]oa[s][.]a[n]no[t]at[i]on[s][.]O[p]er[a]ti[o]n@@;
import org.springframework.web.bind.annotation.*;

@RestController
public class TokenController {

~>    @Operation(summary = "Issue a token via the old flow", deprecated = true)
    @GetMapping("/token")
    public String token(@RequestParam String user, @RequestParam String password) {
        return tokens.issue(user, password);
    }
}
