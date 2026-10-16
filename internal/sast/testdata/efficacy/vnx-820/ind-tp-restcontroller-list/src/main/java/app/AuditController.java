package app;

import java.util.ArrayList;
import java.util.List;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuditController {
    private List<String> events = new ArrayList<>();

    @PostMapping("/audit")
    public void record(@RequestBody String e) {
~>        events.add(e);
    }
}
