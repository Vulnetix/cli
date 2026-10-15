package com.acme.web;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
~>                .allowedOriginPatterns("*")
                .allowCredentials(true);
    }
}

@RestController
~>@CrossOrigin(origins = "*")
class AccountController {
}
