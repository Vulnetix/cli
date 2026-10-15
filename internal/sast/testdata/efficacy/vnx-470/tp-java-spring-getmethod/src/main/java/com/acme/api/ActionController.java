package com.acme.api;

import java.lang.reflect.Method;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ActionController {
    private final AccountService service = new AccountService();

    @GetMapping("/accounts/run")
    public Object run(@RequestParam("action") String action) throws Exception {
~>        Method m = service.getClass().getMethod(action);
        return m.invoke(service);
    }

    @GetMapping("/reports/{type}")
    public Object report(@PathVariable String type) throws Exception {
~>        Class<?> reportClass = Class.forName(
                "com.acme.reports." + type);
        return reportClass.getDeclaredConstructor().newInstance();
    }
}
