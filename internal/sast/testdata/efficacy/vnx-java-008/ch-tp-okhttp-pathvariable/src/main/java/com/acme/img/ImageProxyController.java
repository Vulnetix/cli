package com.acme.img;

import @@sample:o[k]ht[t]p3[.]Ok[H]tt[p]Cl[i]en[t]@@;
import okhttp3.Request;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ImageProxyController {
    private final OkHttpClient http = new OkHttpClient();

    @GetMapping("/img")
    public byte[] image(@RequestParam(name = "src") String imageUrl) throws Exception {
~>        Request request = new Request.Builder().url(imageUrl).build();
        return http.newCall(request).execute().body().bytes();
    }
}
