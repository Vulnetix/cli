package com.acme;
import java.util.List;
public class Auth {
    void verify(String token, List<String> items) {
~>        if (token == null);
        {
            deny();
        }
~>        for (String i : items);
        System.out.println("done");
    }
    void deny() {}
}
