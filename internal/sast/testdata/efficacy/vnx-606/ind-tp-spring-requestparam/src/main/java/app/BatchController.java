package app;

import org.springframework.web.bind.annotation.*;

@RestController
public class BatchController {
    @GetMapping("/batch")
    public String batch(@RequestParam int count) {
        StringBuilder sb = new StringBuilder();
~>        for (int i = 0; i < count; i++) {
            sb.append(i).append(',');
        }
        return sb.toString();
    }
}
