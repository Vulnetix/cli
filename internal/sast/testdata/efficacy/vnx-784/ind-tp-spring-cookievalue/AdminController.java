import org.springframework.web.bind.annotation.*;

@RestController
public class AdminController {
    @GetMapping("/admin")
~>    public String admin(@CookieValue("role") String role) {
        if ("admin".equals(role)) {
            return "ok";
        }
        return "no";
    }
}
