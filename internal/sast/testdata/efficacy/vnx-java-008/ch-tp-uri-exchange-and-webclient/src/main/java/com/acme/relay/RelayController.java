package com.acme.relay;

import java.net.URI;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

@RestController
public class RelayController {
    private final RestTemplate rest = new RestTemplate();

    @GetMapping("/relay")
    public String relay(HttpServletRequest request) throws Exception {
        String url = request.getParameter("url");
        URI target = new URI(url);
~>        return rest.exchange(target, HttpMethod.GET, null, String.class).getBody();
    }

    @GetMapping("/raw")
    public byte[] raw(HttpServletRequest request) throws Exception {
~>        return new URL(request.getParameter("u")).openStream().readAllBytes();
    }

    @GetMapping("/base")
    public String base(@RequestHeader("X-Upstream") String upstream) {
~>        return WebClient.create(upstream).get().retrieve().bodyToMono(String.class).block();
    }
}
