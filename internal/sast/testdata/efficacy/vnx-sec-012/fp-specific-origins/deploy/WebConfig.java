@Configuration
public class WebConfig implements WebMvcConfigurer {
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**").allowedOrigins("https://app.example.com");
    }
}

@CrossOrigin(origins = "https://app.example.com")
class AccountController {
}
