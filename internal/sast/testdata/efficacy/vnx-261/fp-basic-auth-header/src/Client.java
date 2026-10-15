package src;

import java.util.Base64;

class Client {
    String header(String username, String password) {
        return "Basic " + Base64.getEncoder().encodeToString(username.concat(":").concat(password).getBytes());
    }
}
