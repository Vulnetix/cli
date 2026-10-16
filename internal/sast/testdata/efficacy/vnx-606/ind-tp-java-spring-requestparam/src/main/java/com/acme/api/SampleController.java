package com.acme.api;

import java.util.ArrayList;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SampleController {

    private final SampleRepository repo;

    public SampleController(SampleRepository repo) {
        this.repo = repo;
    }

    @GetMapping("/samples")
    public List<Sample> samples(@RequestParam(name = "batches", defaultValue = "1") int batches) {
        List<Sample> out = new ArrayList<>();
~>        for (int b = 0; b < batches; b++) {
            out.addAll(repo.nextBatch());
        }
        return out;
    }

    @GetMapping("/retry/{attempts}")
    public String retry(@PathVariable int attempts) {
~>        for (int i = 0; i < attempts; ++i) {
            if (repo.ping()) {
                return "ok";
            }
        }
        return "down";
    }
}
