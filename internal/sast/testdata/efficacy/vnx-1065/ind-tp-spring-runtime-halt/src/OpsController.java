package ops;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OpsController {
    @PostMapping("/kill")
    public void kill() {
        Runtime rt = Runtime.getRuntime();
~>        rt.halt(1);
    }

    @PostMapping("/stop")
    public void stop() {
~>        Runtime.getRuntime().exit(2);
    }
}
