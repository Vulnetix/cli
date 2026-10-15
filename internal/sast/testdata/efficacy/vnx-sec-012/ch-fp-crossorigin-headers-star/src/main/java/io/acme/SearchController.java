package io.acme;

import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin(origins = "https://app.acme.io", allowedHeaders = "*")
public class SearchController {
    @CrossOrigin(origins = {"https://admin.acme.io"}, methods = {RequestMethod.GET}, exposedHeaders = "*")
    @GetMapping("/search")
    public String search() { return "ok"; }
}
