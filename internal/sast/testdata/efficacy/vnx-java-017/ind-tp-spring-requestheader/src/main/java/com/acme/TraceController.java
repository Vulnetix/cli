package com.acme;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
@RestController
public class TraceController {
    @GetMapping("/trace")
    public String trace(@RequestHeader("X-Trace") String trace, HttpServletResponse resp) {
~>        resp.addHeader("X-Trace-Echo", trace);
        return "ok";
    }
}
